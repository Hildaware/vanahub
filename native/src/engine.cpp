#include "vanahub/api.h"
#include "vanahub/core.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <mz.h>
#include <mz_strm.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>
#include <monocypher-ed25519.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string json_string(const std::string& source, const char* key) {
    const auto marker = "\"" + std::string(key) + "\"";
    auto position = source.find(marker);
    if (position == std::string::npos) return {};
    position = source.find(':', position + marker.size());
    if (position == std::string::npos) return {};
    position = source.find_first_not_of(" \t\r\n", position + 1);
    if (position == std::string::npos || source[position] != '"') return {};
    std::string result;
    for (++position; position < source.size(); ++position) {
        const auto c = source[position];
        if (c == '"') return result;
        if (c != '\\') { result += c; continue; }
        if (++position >= source.size()) return {};
        switch (source[position]) {
            case '"': result += '"'; break;
            case '\\': result += '\\'; break;
            case '/': result += '/'; break;
            case 'b': result += '\b'; break;
            case 'f': result += '\f'; break;
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            default: return {};
        }
    }
    return {};
}

std::vector<std::uint8_t> base64_decode(std::string_view value) {
    static constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<std::uint8_t> output;
    std::uint32_t buffer{}; int bits{};
    for (const char c : value) {
        if (c == '=') break;
        const auto position = alphabet.find(c);
        if (position == std::string_view::npos) return {};
        buffer = (buffer << 6) | static_cast<std::uint32_t>(position); bits += 6;
        if (bits >= 8) { bits -= 8; output.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xff)); }
    }
    return output;
}

bool verify_catalog_signature(const fs::path& index, const fs::path& detached,
                              const std::string& encoded_public_key, std::string& error) {
    const auto public_key = base64_decode(encoded_public_key);
    std::ifstream signature_input(detached, std::ios::binary);
    const std::string signature_json((std::istreambuf_iterator<char>(signature_input)), {});
    const auto signature = base64_decode(json_string(signature_json, "signature"));
    std::ifstream index_input(index, std::ios::binary);
    const std::vector<std::uint8_t> payload((std::istreambuf_iterator<char>(index_input)), {});
    if (public_key.size() != 32 || signature.size() != 64 || payload.empty()) {
        error = "Malformed catalog signature or public key"; return false;
    }
    if (crypto_ed25519_check(signature.data(), public_key.data(), payload.data(), payload.size()) != 0) {
        error = "Built-in catalog signature verification failed"; return false;
    }
    return true;
}

bool json_bool(const std::string& source, const char* key, bool fallback = false) {
    const std::regex expression("\\\"" + std::string(key) + "\\\"\\s*:\\s*(true|false)");
    std::smatch match;
    return std::regex_search(source, match, expression) ? match[1].str() == "true" : fallback;
}

std::wstring widen(const std::string& value) {
    if (value.empty()) return {};
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count);
    return result;
}

std::string sha256_file(const fs::path& path) {
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD object_size{}, result_size{};
    std::vector<unsigned char> object;
    std::array<unsigned char, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &result_size, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); return {};
    }
    object.resize(object_size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); return {};
    }
    std::ifstream input(path, std::ios::binary);
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), buffer.size());
        if (input.gcount() > 0 && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(input.gcount()), 0) < 0) break;
    }
    const auto ok = input.eof() && BCryptFinishHash(hash, digest.data(), digest.size(), 0) >= 0;
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) return {};
    std::ostringstream output;
    for (const auto byte : digest) output << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    return output.str();
}

struct job {
    vh_job_id id{};
    std::atomic_bool cancel{};
    mutable std::mutex mutex;
    std::string phase{"queued"};
    std::string message;
    std::uint64_t completed{};
    std::uint64_t total{};
    bool terminal{};
    vh_result result{VH_OK};
    std::jthread worker;

    void update(std::string next, std::string detail = {}) {
        std::scoped_lock lock(mutex); phase = std::move(next); message = std::move(detail);
    }
    void finish(vh_result value, std::string detail = {}) {
        std::scoped_lock lock(mutex); result = value; terminal = true;
        phase = value == VH_OK ? "complete" : (value == VH_CANCELLED ? "cancelled" : "failed");
        message = std::move(detail);
    }
    std::string status() const {
        std::scoped_lock lock(mutex);
        std::ostringstream out;
        out << "{\"schemaVersion\":1,\"jobId\":" << id
            << ",\"phase\":\"" << vanahub::json_escape(phase) << "\""
            << ",\"message\":\"" << vanahub::json_escape(message) << "\""
            << ",\"completed\":" << completed << ",\"total\":" << total
            << ",\"terminal\":" << (terminal ? "true" : "false")
            << ",\"result\":" << static_cast<int>(result) << "}";
        return out.str();
    }
};

bool is_builtin_artifact_host(std::wstring host) {
    std::transform(host.begin(), host.end(), host.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return host == L"github.com" || host == L"objects.githubusercontent.com" ||
        host == L"release-assets.githubusercontent.com";
}

bool is_local_host(std::wstring host) {
    std::transform(host.begin(), host.end(), host.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return host == L"localhost" || host == L"127.0.0.1" || host == L"::1" || host == L"[::1]";
}

bool ipv4_is_public(std::uint32_t network_address) {
    const auto value = ntohl(network_address);
    const auto first = value >> 24;
    const auto second = (value >> 16) & 0xff;
    if (first == 0 || first == 10 || first == 127 || first >= 224) return false;
    if (first == 100 && second >= 64 && second <= 127) return false;
    if (first == 169 && second == 254) return false;
    if (first == 172 && second >= 16 && second <= 31) return false;
    if (first == 192 && (second == 0 || second == 168)) return false;
    if (first == 198 && (second == 18 || second == 19)) return false;
    return true;
}

bool host_resolves_public(const std::wstring& host, std::string& error) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { error = "Could not initialize DNS validation"; return false; }
    ADDRINFOW hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    ADDRINFOW* addresses{};
    const auto resolved = GetAddrInfoW(host.c_str(), nullptr, &hints, &addresses);
    bool any{}; bool public_only = resolved == 0;
    for (auto* address = addresses; address; address = address->ai_next) {
        any = true;
        if (address->ai_family == AF_INET) {
            public_only = public_only && ipv4_is_public(reinterpret_cast<sockaddr_in*>(address->ai_addr)->sin_addr.s_addr);
        } else if (address->ai_family == AF_INET6) {
            const auto* value = &reinterpret_cast<sockaddr_in6*>(address->ai_addr)->sin6_addr;
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(value);
            const auto mapped = IN6_IS_ADDR_V4MAPPED(value) != 0;
            const auto private_v6 = IN6_IS_ADDR_UNSPECIFIED(value) || IN6_IS_ADDR_LOOPBACK(value) ||
                IN6_IS_ADDR_LINKLOCAL(value) || IN6_IS_ADDR_SITELOCAL(value) ||
                IN6_IS_ADDR_MULTICAST(value) || (bytes[0] & 0xfe) == 0xfc;
            std::uint32_t mapped_v4{};
            if (mapped) std::memcpy(&mapped_v4, bytes + 12, sizeof(mapped_v4));
            public_only = public_only && !private_v6 && (!mapped || ipv4_is_public(mapped_v4));
        } else public_only = false;
    }
    if (addresses) FreeAddrInfoW(addresses);
    WSACleanup();
    if (!any || !public_only) error = "Remote host did not resolve exclusively to public addresses";
    return any && public_only;
}

bool download_file(job& current, const std::string& url, const fs::path& destination,
                   bool allow_local, bool github_only, std::string& error) {
    if (allow_local && url.starts_with("file:///")) {
        if (github_only) { error = "Built-in artifacts cannot use local URLs"; return false; }
        auto local = url.substr(8);
        std::replace(local.begin(), local.end(), '/', '\\');
        std::ifstream input(fs::path(widen(local)), std::ios::binary);
        if (!input) { error = "Local developer file could not be opened"; return false; }
        fs::create_directories(destination.parent_path());
        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        std::array<char, 64 * 1024> buffer{};
        while (input && !current.cancel.load()) {
            input.read(buffer.data(), buffer.size());
            if (input.gcount() > 0) { output.write(buffer.data(), input.gcount()); current.completed += input.gcount(); }
            if (current.completed > 50ull * 1024 * 1024) { error = "Local file size limit exceeded"; return false; }
        }
        if (current.cancel.load()) { error = "Cancelled"; return false; }
        return input.eof() && output.good();
    }
    const auto wide_url = widen(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &components)) { error = "Invalid URL"; return false; }
    const std::wstring parsed_host(components.lpszHostName, components.dwHostNameLength);
    const auto local_http = allow_local && components.nScheme == INTERNET_SCHEME_HTTP &&
        is_local_host(parsed_host);
    if (components.nScheme != INTERNET_SCHEME_HTTPS && !local_http) {
        error = "Only HTTPS is accepted outside developer-mode localhost"; return false;
    }
    if (!local_http && !host_resolves_public(parsed_host, error)) return false;
    if (github_only && !is_builtin_artifact_host(parsed_host)) {
        error = "Built-in artifacts must originate from GitHub Releases"; return false;
    }
    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength) path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    HINTERNET session = WinHttpOpen(L"vanahub-engine/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nullptr, nullptr, 0);
    if (!session) { error = "WinHttpOpen failed"; return false; }
    WinHttpSetTimeouts(session, 15000, 15000, 30000, 30000);
    HINTERNET connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0) : nullptr;
    DWORD redirects = 5;
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    if (request) {
        WinHttpSetOption(request, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS, &redirects, sizeof(redirects));
        WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
    }
    bool ok = request && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(request, nullptr);
    DWORD status{}, status_size = sizeof(status);
    if (ok) ok = WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX) && status >= 200 && status < 300;
    if (ok) {
        DWORD final_size{};
        WinHttpQueryOption(request, WINHTTP_OPTION_URL, nullptr, &final_size);
        std::vector<wchar_t> final_url(final_size / sizeof(wchar_t) + 1);
        URL_COMPONENTS final_components{};
        final_components.dwStructSize = sizeof(final_components);
        final_components.dwSchemeLength = static_cast<DWORD>(-1);
        final_components.dwHostNameLength = static_cast<DWORD>(-1);
        ok = final_size > sizeof(wchar_t) &&
            WinHttpQueryOption(request, WINHTTP_OPTION_URL, final_url.data(), &final_size) &&
            WinHttpCrackUrl(final_url.data(), 0, 0, &final_components);
        if (ok) {
            const std::wstring final_host(final_components.lpszHostName, final_components.dwHostNameLength);
            const auto final_local = allow_local && final_components.nScheme == INTERNET_SCHEME_HTTP && is_local_host(final_host);
            ok = final_local || (final_components.nScheme == INTERNET_SCHEME_HTTPS && host_resolves_public(final_host, error));
            if (ok && github_only) ok = is_builtin_artifact_host(final_host);
        }
        if (!ok && error.empty()) error = github_only
            ? "Built-in artifact redirected outside approved GitHub hosts"
            : "Download redirected to an unsafe location";
    }
    if (!ok && error.empty()) error = "HTTPS request failed or returned a non-success status";
    std::ofstream output;
    if (ok) { fs::create_directories(destination.parent_path()); output.open(destination, std::ios::binary | std::ios::trunc); ok = output.good(); }
    std::array<char, 64 * 1024> buffer{};
    while (ok && !current.cancel.load()) {
        DWORD available{};
        if (!WinHttpQueryDataAvailable(request, &available)) { ok = false; break; }
        if (!available) break;
        while (available && !current.cancel.load()) {
            DWORD read{};
            const auto amount = static_cast<DWORD>(std::min<std::size_t>(available, buffer.size()));
            if (!WinHttpReadData(request, buffer.data(), amount, &read) || !read) { ok = false; break; }
            output.write(buffer.data(), read); current.completed += read; available -= read;
            if (current.completed > 50ull * 1024 * 1024) { error = "Download size limit exceeded"; ok = false; break; }
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    output.close();
    if (current.cancel.load()) { error = "Cancelled"; return false; }
    if (!ok && error.empty()) error = "Download read failed";
    return ok;
}

bool inspect_and_extract(job& current, const fs::path& archive, const fs::path& staging,
                         const std::string& root, const std::string& entrypoint,
                         bool allow_elevated, bool allow_engine_binary,
                         std::vector<std::string>& owned, std::string& error) {
    void* reader = mz_zip_reader_create();
    if (!reader || mz_zip_reader_open_file(reader, archive.string().c_str()) != MZ_OK) {
        if (reader) mz_zip_reader_delete(&reader); error = "Unable to open ZIP"; return false;
    }
    std::map<std::string, std::string> destinations;
    std::uint64_t expanded{};
    bool found_entrypoint{};
    auto code = mz_zip_reader_goto_first_entry(reader);
    while (code == MZ_OK) {
        mz_zip_file* info{};
        if (mz_zip_reader_entry_get_info(reader, &info) != MZ_OK || !info || !info->filename) { error = "Invalid ZIP entry"; break; }
        std::string name(info->filename);
        while (!name.empty() && name.back() == '/') name.pop_back();
        if (name.empty()) { code = mz_zip_reader_goto_next_entry(reader); continue; }
        const auto is_directory = mz_zip_reader_entry_is_dir(reader) == MZ_OK;
        std::string reason;
        if (!vanahub::is_safe_relative_path(name, &reason)) { error = "Unsafe ZIP path: " + name + " (" + reason + ")"; break; }
        if (mz_zip_attrib_is_symlink(info->external_fa, info->version_madeby) == MZ_OK || info->linkname != nullptr) {
            error = "ZIP symlinks are prohibited"; break;
        }
        if ((info->flag & MZ_ZIP_FLAG_ENCRYPTED) != 0) { error = "Encrypted ZIP entries are prohibited"; break; }
        if (info->compression_method != MZ_COMPRESS_METHOD_STORE && info->compression_method != MZ_COMPRESS_METHOD_DEFLATE) {
            error = "Unsupported ZIP compression method"; break;
        }
        expanded += static_cast<std::uint64_t>(info->uncompressed_size);
        if (expanded > 200ull * 1024 * 1024 || info->uncompressed_size > 50ll * 1024 * 1024) { error = "ZIP expansion limit exceeded"; break; }
        if (info->compressed_size > 0 && info->uncompressed_size / info->compressed_size > 200) {
            error = "Suspicious ZIP compression ratio"; break;
        }
        const auto prefix = root.empty() ? std::string{} : root + "/";
        if (!prefix.empty() && name == root && is_directory) {
            code = mz_zip_reader_goto_next_entry(reader); continue;
        }
        if (!prefix.empty() && !name.starts_with(prefix)) { error = "ZIP entry outside archiveRoot"; break; }
        auto relative = prefix.empty() ? name : name.substr(prefix.size());
        if (relative.empty()) { code = mz_zip_reader_goto_next_entry(reader); continue; }
        const auto engine_binary = allow_engine_binary &&
            vanahub::ascii_casefold(relative) == "bin/vanahub_engine.dll";
        if (!vanahub::is_allowed_extension(relative) && !engine_binary && !is_directory) {
            error = "Prohibited archive file type: " + relative; break;
        }
        const auto folded = vanahub::ascii_casefold(relative);
        if (destinations.contains(folded)) { error = "Duplicate or case-colliding ZIP entry"; break; }
        destinations.emplace(folded, relative);
        if (destinations.size() > 4096) { error = "ZIP entry-count limit exceeded"; break; }
        if (vanahub::ascii_casefold(relative) == vanahub::ascii_casefold(entrypoint)) found_entrypoint = true;
        code = mz_zip_reader_goto_next_entry(reader);
    }
    if (error.empty() && !found_entrypoint) error = "Declared entrypoint not found";
    if (!error.empty()) { mz_zip_reader_close(reader); mz_zip_reader_delete(&reader); return false; }

    fs::create_directories(staging);
    code = mz_zip_reader_goto_first_entry(reader);
    while (code == MZ_OK && !current.cancel.load()) {
        mz_zip_file* info{}; mz_zip_reader_entry_get_info(reader, &info);
        std::string name(info->filename ? info->filename : "");
        while (!name.empty() && name.back() == '/') name.pop_back();
        if (!name.empty()) {
            const auto prefix = root.empty() ? std::string{} : root + "/";
            if (prefix.empty() || name.starts_with(prefix)) {
                const auto relative = prefix.empty() ? name : name.substr(prefix.size());
                if (!relative.empty()) {
                    const auto destination = staging / fs::path(widen(relative));
                    if (mz_zip_reader_entry_is_dir(reader) == MZ_OK) fs::create_directories(destination);
                    else {
                        fs::create_directories(destination.parent_path());
                        if (mz_zip_reader_entry_save_file(reader, destination.string().c_str()) != MZ_OK) { error = "ZIP extraction failed"; break; }
                        owned.push_back(relative);
                        if (destination.extension() == L".lua") {
                            std::ifstream lua(destination, std::ios::binary);
                            std::string text((std::istreambuf_iterator<char>(lua)), {});
                            if (!allow_elevated && !vanahub::scan_lua(text, relative).empty()) { error = "Lua source violates restricted policy: " + relative; break; }
                        }
                    }
                }
            }
        }
        code = mz_zip_reader_goto_next_entry(reader);
    }
    mz_zip_reader_close(reader); mz_zip_reader_delete(&reader);
    if (current.cancel.load()) error = "Cancelled";
    return error.empty();
}

void write_ownership(const fs::path& root, const std::vector<std::string>& files) {
    std::ofstream output(root / ".vanahub-owned", std::ios::binary | std::ios::trunc);
    for (const auto& file : files) output << file << '\n';
}

std::vector<std::string> read_ownership(const fs::path& root) {
    std::vector<std::string> files;
    std::ifstream input(root / ".vanahub-owned", std::ios::binary);
    for (std::string line; std::getline(input, line);) if (vanahub::is_safe_relative_path(line)) files.push_back(line);
    return files;
}

} // namespace

struct vh_engine {
    fs::path install_root;
    fs::path cache_root;
    std::string builtin_public_key;
    std::atomic<vh_job_id> next_id{1};
    std::mutex jobs_mutex;
    std::mutex mutation_mutex;
    std::map<vh_job_id, std::shared_ptr<job>> jobs;
    std::atomic_bool stopping{};
};

namespace {

void execute_job(vh_engine* engine, const std::shared_ptr<job>& current, std::string request) {
    const auto operation = json_string(request, "operation");
    const auto package_id = json_string(request, "packageId");
    if (!vanahub::is_safe_package_id(package_id)) { current->finish(VH_INVALID_ARGUMENT, "Invalid packageId"); return; }

    if (operation == "fetchRepository") {
        const auto url = json_string(request, "url");
        const auto expected_hash = vanahub::ascii_casefold(json_string(request, "sha256"));
        const auto repositories = engine->cache_root / L"repositories";
        const auto destination = repositories / (widen(package_id) + L".json");
        const auto partial = destination.wstring() + L".part";
        const auto signature_partial = destination.wstring() + L".sig.part";
        current->update("downloading", "Refreshing repository index");
        std::string error;
        if (!download_file(*current, url, partial, json_bool(request, "allowLocal", false), false, error)) {
            std::error_code ec; fs::remove(partial, ec);
            current->finish(current->cancel.load() ? VH_CANCELLED : VH_NETWORK_ERROR, error); return;
        }
        if (!expected_hash.empty() && sha256_file(partial) != expected_hash) {
            std::error_code ec; fs::remove(partial, ec);
            current->finish(VH_HASH_MISMATCH, "Repository SHA-256 mismatch"); return;
        }
        if (json_bool(request, "requireSignature", false)) {
            const auto signature_url = json_string(request, "signatureUrl");
            if (engine->builtin_public_key.empty() || signature_url.empty() ||
                !download_file(*current, signature_url, signature_partial, false, false, error) ||
                !verify_catalog_signature(partial, signature_partial, engine->builtin_public_key, error)) {
                std::error_code ec; fs::remove(partial, ec); fs::remove(signature_partial, ec);
                current->finish(VH_SCAN_REJECTED, error.empty() ? "Catalog signature is required" : error); return;
            }
        }
        std::error_code ec; fs::create_directories(repositories, ec); fs::rename(partial, destination, ec);
        if (ec) { fs::remove(partial, ec); current->finish(VH_FILESYSTEM_ERROR, "Could not activate repository cache"); return; }
        std::error_code cleanup_ec; fs::remove(signature_partial, cleanup_ec);
        current->finish(VH_OK, destination.string()); return;
    }

    std::scoped_lock mutation(engine->mutation_mutex);
    if (current->cancel.load()) { current->finish(VH_CANCELLED); return; }
    auto target = engine->install_root / widen(package_id);

    if (operation == "uninstall") {
        current->update("committing", "Removing package-owned files");
        std::error_code ec;
        for (const auto& relative : read_ownership(target)) fs::remove(target / widen(relative), ec);
        fs::remove(target / L".vanahub-owned", ec);
        for (auto it = fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied, ec); !ec && it != fs::recursive_directory_iterator(); ++it) {}
        fs::remove(target, ec);
        current->finish(VH_OK); return;
    }
    const auto self_update = operation == "stageSelfUpdate";
    if (operation != "install" && operation != "update" && !self_update) {
        current->finish(VH_INVALID_ARGUMENT, "Unsupported operation"); return;
    }

    const auto url = json_string(request, "url");
    const auto expected_hash = vanahub::ascii_casefold(json_string(request, "sha256"));
    const auto root = json_string(request, "archiveRoot");
    const auto entrypoint = json_string(request, "entrypoint");
    const auto version = json_string(request, "version");
    const auto allow_elevated = json_bool(request, "allowElevated", false);
    if (url.empty() || expected_hash.size() != 64 || !vanahub::is_safe_relative_path(entrypoint) ||
        (self_update && (package_id != "vanahub" || !vanahub::is_safe_package_id(version) || allow_elevated ||
                         !json_bool(request, "githubOnly", false) || json_bool(request, "allowLocal", false)))) {
        current->finish(VH_INVALID_ARGUMENT, "Invalid install request"); return;
    }
    if (self_update) target = engine->install_root / L"vanahub" / L"versions" / widen(version);

    const auto transaction = engine->cache_root / L"transactions" / std::to_wstring(current->id);
    const auto archive = transaction / L"package.zip.part";
    const auto staging = transaction / L"staging";
    const auto backup = transaction / L"backup";
    std::error_code ec;
    fs::remove_all(transaction, ec); fs::create_directories(transaction, ec);
    { std::ofstream journal(transaction / L"transaction.json"); journal << "{\"phase\":\"downloading\",\"packageId\":\"" << vanahub::json_escape(package_id) << "\"}\n"; }

    current->update("downloading", "Downloading release asset");
    std::string error;
    if (!download_file(*current, url, archive, json_bool(request, "allowLocal", false),
                       json_bool(request, "githubOnly", false), error)) {
        fs::remove_all(transaction, ec);
        current->finish(current->cancel.load() ? VH_CANCELLED : VH_NETWORK_ERROR, error); return;
    }
    current->update("hashing", "Verifying SHA-256");
    if (sha256_file(archive) != expected_hash) { fs::remove_all(transaction, ec); current->finish(VH_HASH_MISMATCH, "SHA-256 mismatch"); return; }
    current->update("inspecting", "Inspecting archive paths and source");
    std::vector<std::string> owned;
    if (!inspect_and_extract(*current, archive, staging, root, entrypoint, allow_elevated,
                             self_update, owned, error)) {
        fs::remove_all(transaction, ec); current->finish(error.find("policy") != std::string::npos ? VH_SCAN_REJECTED : VH_ARCHIVE_ERROR, error); return;
    }
    if (self_update) {
        write_ownership(staging, owned);
        current->update("committing", "Staging package manager update for next launch");
        if (fs::exists(target)) {
            fs::remove_all(transaction, ec);
            current->finish(VH_FILESYSTEM_ERROR, "This package manager version is already staged"); return;
        }
        fs::create_directories(target.parent_path(), ec);
        fs::rename(staging, target, ec);
        if (ec) { fs::remove_all(transaction, ec); current->finish(VH_FILESYSTEM_ERROR, "Could not stage package manager update"); return; }
        const auto manager_root = engine->install_root / L"vanahub";
        const auto pending_tmp = manager_root / L"pending.txt.tmp";
        { std::ofstream pending(pending_tmp, std::ios::binary | std::ios::trunc); pending << version << '\n'; }
        fs::rename(pending_tmp, manager_root / L"pending.txt", ec);
        if (ec) {
            fs::remove_all(target, ec); fs::remove_all(transaction, ec);
            current->finish(VH_FILESYSTEM_ERROR, "Could not activate staged update marker"); return;
        }
        fs::remove_all(transaction, ec); current->finish(VH_OK); return;
    }

    // Preserve untracked files from an existing managed installation.
    const auto previous_owned = read_ownership(target);
    std::set<std::string> previous(previous_owned.begin(), previous_owned.end());
    if (fs::exists(target)) {
        for (fs::recursive_directory_iterator it(target, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; ++it) {
            if (!it->is_regular_file()) continue;
            auto relative = fs::relative(it->path(), target, ec).generic_string();
            if (relative == ".vanahub-owned" || previous.contains(relative)) continue;
            auto destination = staging / fs::relative(it->path(), target, ec);
            if (!fs::exists(destination)) { fs::create_directories(destination.parent_path(), ec); fs::copy_file(it->path(), destination, ec); }
        }
    }
    write_ownership(staging, owned);
    current->update("backing_up", "Backing up installed version");
    if (fs::exists(target)) { fs::remove_all(backup, ec); fs::rename(target, backup, ec); if (ec) { current->finish(VH_FILESYSTEM_ERROR, "Could not back up existing addon"); return; } }
    current->update("committing", "Activating staged version");
    fs::create_directories(target.parent_path(), ec); fs::rename(staging, target, ec);
    if (ec) {
        std::error_code rollback_ec;
        if (fs::exists(backup)) fs::rename(backup, target, rollback_ec);
        current->finish(VH_FILESYSTEM_ERROR, "Commit failed; previous version restored"); return;
    }
    fs::remove_all(transaction, ec);
    current->finish(VH_OK);
}

} // namespace

uint32_t VH_CALL vh_abi_version(void) { return VH_ABI_VERSION; }

vh_result VH_CALL vh_engine_create(const char* config_json, vh_engine** output) {
    if (!config_json || !output) return VH_INVALID_ARGUMENT;
    const std::string config(config_json);
    const auto install = json_string(config, "installRoot");
    const auto cache = json_string(config, "cacheRoot");
    if (install.empty() || cache.empty()) return VH_INVALID_ARGUMENT;
    try {
        auto engine = std::make_unique<vh_engine>();
        engine->install_root = fs::path(widen(install));
        engine->cache_root = fs::path(widen(cache));
        engine->builtin_public_key = json_string(config, "builtinPublicKey");
        fs::create_directories(engine->install_root);
        fs::create_directories(engine->cache_root / L"transactions");
        *output = engine.release(); return VH_OK;
    } catch (...) { return VH_INTERNAL_ERROR; }
}

vh_result VH_CALL vh_engine_recover(vh_engine* engine) {
    if (!engine) return VH_INVALID_ARGUMENT;
    std::error_code ec;
    const auto transactions = engine->cache_root / L"transactions";
    if (!fs::exists(transactions)) return VH_OK;
    for (const auto& item : fs::directory_iterator(transactions, ec)) {
        const auto journal_path = item.path() / L"transaction.json";
        std::ifstream input(journal_path, std::ios::binary);
        const std::string journal((std::istreambuf_iterator<char>(input)), {});
        const auto package_id = json_string(journal, "packageId");
        if (vanahub::is_safe_package_id(package_id)) {
            const auto target = engine->install_root / widen(package_id);
            const auto backup = item.path() / L"backup";
            if (!fs::exists(target) && fs::exists(backup)) fs::rename(backup, target, ec);
        }
        if (!ec) fs::remove_all(item.path(), ec);
        if (ec) return VH_FILESYSTEM_ERROR;
    }
    return ec ? VH_FILESYSTEM_ERROR : VH_OK;
}

vh_job_id VH_CALL vh_job_start(vh_engine* engine, const char* request_json) {
    if (!engine || !request_json || engine->stopping.load()) return 0;
    auto current = std::make_shared<job>();
    current->id = engine->next_id.fetch_add(1);
    { std::scoped_lock lock(engine->jobs_mutex); engine->jobs.emplace(current->id, current); }
    const std::string request(request_json);
    current->worker = std::jthread([engine, current, request] { execute_job(engine, current, request); });
    return current->id;
}

vh_result VH_CALL vh_job_poll(vh_engine* engine, vh_job_id id, char* buffer, uint32_t capacity, uint32_t* required) {
    if (!engine || !required) return VH_INVALID_ARGUMENT;
    std::shared_ptr<job> current;
    { std::scoped_lock lock(engine->jobs_mutex); const auto it = engine->jobs.find(id); if (it == engine->jobs.end()) return VH_NOT_FOUND; current = it->second; }
    const auto status = current->status(); *required = static_cast<uint32_t>(status.size() + 1);
    if (!buffer || capacity < *required) return VH_BUFFER_TOO_SMALL;
    memcpy(buffer, status.c_str(), status.size() + 1); return VH_OK;
}

vh_result VH_CALL vh_job_cancel(vh_engine* engine, vh_job_id id) {
    if (!engine) return VH_INVALID_ARGUMENT;
    std::scoped_lock lock(engine->jobs_mutex); const auto it = engine->jobs.find(id);
    if (it == engine->jobs.end()) return VH_NOT_FOUND; it->second->cancel = true; return VH_OK;
}

void VH_CALL vh_job_release(vh_engine* engine, vh_job_id id) {
    if (!engine) return;
    std::shared_ptr<job> current;
    { std::scoped_lock lock(engine->jobs_mutex); const auto it = engine->jobs.find(id); if (it == engine->jobs.end()) return; current = it->second; }
    { std::scoped_lock lock(current->mutex); if (!current->terminal) return; }
    std::scoped_lock lock(engine->jobs_mutex); engine->jobs.erase(id);
}

void VH_CALL vh_engine_destroy(vh_engine* engine) {
    if (!engine) return; engine->stopping = true;
    std::vector<std::shared_ptr<job>> jobs;
    { std::scoped_lock lock(engine->jobs_mutex); for (auto& [_, value] : engine->jobs) { value->cancel = true; jobs.push_back(value); } }
    jobs.clear(); delete engine;
}
