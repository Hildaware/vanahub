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

bool valid_sha256(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::wstring widen(const std::string& value);
std::string sha256_file(const fs::path& path);

std::string read_small_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::string value((std::istreambuf_iterator<char>(input)), {});
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();
    return value;
}

bool activate_pointer(const fs::path& repository_root, const std::string& digest, std::string& error) {
    const auto pointer = repository_root / L"current";
    const auto partial = repository_root / L"current.part";
    {
        std::ofstream output(partial, std::ios::binary | std::ios::trunc);
        output << digest << '\n';
        if (!output.good()) { error = "Could not write repository cache pointer"; return false; }
    }
    if (!MoveFileExW(partial.c_str(), pointer.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ec; fs::remove(partial, ec);
        error = "Could not activate repository cache pointer"; return false;
    }
    return true;
}

bool activate_signed_repository(const fs::path& repository_root, const fs::path& index_partial,
                                const fs::path& signature_partial, const std::string& digest,
                                std::string& activated_path, std::string& error) {
    const auto previous = read_small_text(repository_root / L"current");
    const auto generations = repository_root / L"generations";
    const auto generation = generations / widen(digest);
    std::error_code ec;
    fs::create_directories(generations, ec);
    if (ec) { error = "Could not create repository cache"; return false; }
    fs::remove_all(generation, ec); ec.clear();
    fs::create_directories(generation, ec);
    if (ec) { error = "Could not create repository cache generation"; return false; }
    fs::rename(index_partial, generation / L"index.json", ec);
    if (!ec) fs::rename(signature_partial, generation / L"index.json.sig", ec);
    if (ec) {
        fs::remove_all(generation, ec);
        error = "Could not stage repository cache generation"; return false;
    }
    if (!activate_pointer(repository_root, digest, error)) return false;
    for (const auto& item : fs::directory_iterator(generations, ec)) {
        const auto name = item.path().filename().string();
        if (item.is_directory() && name != digest && name != previous) fs::remove_all(item.path(), ec);
        ec.clear();
    }
    activated_path = (generation / L"index.json").string();
    return true;
}

bool load_signed_repository_cache(const fs::path& repository_root, const std::string& public_key,
                                  std::string& index_path, std::string& error) {
    const auto generations = repository_root / L"generations";
    std::vector<std::string> candidates;
    const auto current = read_small_text(repository_root / L"current");
    if (valid_sha256(current)) candidates.push_back(current);
    std::error_code ec;
    if (fs::exists(generations)) {
        for (const auto& item : fs::directory_iterator(generations, ec)) {
            const auto name = item.path().filename().string();
            if (item.is_directory() && valid_sha256(name) && name != current) candidates.push_back(name);
        }
    }
    for (const auto& candidate : candidates) {
        const auto generation = generations / widen(candidate);
        const auto index = generation / L"index.json";
        const auto signature = generation / L"index.json.sig";
        std::string verification_error;
        if (sha256_file(index) == candidate &&
            verify_catalog_signature(index, signature, public_key, verification_error)) {
            if (candidate != current && !activate_pointer(repository_root, candidate, error)) return false;
            index_path = index.string(); return true;
        }
        fs::remove_all(generation, ec); ec.clear();
    }
    error = candidates.empty() ? "No verified repository cache is available"
                               : "No valid repository cache generation remains";
    return false;
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
        if (mz_zip_attrib_is_symlink(info->external_fa, info->version_madeby) == MZ_OK ||
            (info->linkname != nullptr && *info->linkname != '\0')) {
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
    fs::path config_root;
    fs::path cache_root;
    std::string builtin_public_key;
    std::atomic<vh_job_id> next_id{1};
    std::mutex jobs_mutex;
    std::mutex mutation_mutex;
    std::mutex repository_mutex;
    std::mutex media_mutex;
    std::map<vh_job_id, std::shared_ptr<job>> jobs;
    std::atomic_bool stopping{};
};

namespace {

std::vector<std::string> split_ids(const std::string& value) {
    std::vector<std::string> result;
    std::size_t start{};
    while (start <= value.size()) {
        const auto end = value.find(';', start);
        const auto id = value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!id.empty() && vanahub::is_safe_package_id(id) && id != "vanahub") result.push_back(id);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

fs::path config_directory(const fs::path& root, const std::string& package_id) {
    std::error_code ec;
    const auto folded = vanahub::ascii_casefold(package_id);
    for (const auto& item : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
        if (item.is_directory(ec) && vanahub::ascii_casefold(item.path().filename().string()) == folded)
            return item.path();
        ec.clear();
    }
    return root / widen(package_id);
}

bool read_setting(const fs::path& path, std::string& contents, std::string& error) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > 32ull * 1024 * 1024) { error = "Settings file exceeds the size limit"; return false; }
    std::ifstream input(path, std::ios::binary);
    if (!input) { error = "Could not open settings file"; return false; }
    contents.assign(std::istreambuf_iterator<char>(input), {});
    if (input.bad()) { error = "Could not read settings file"; return false; }
    return true;
}

bool scan_setting_file(const fs::path& path, const std::string& relative, std::string& error) {
    std::string contents;
    if (!read_setting(path, contents, error)) return false;
    const auto findings = vanahub::scan_setting(contents, relative);
    if (!findings.empty()) { error = findings.front().message + ": " + relative; return false; }
    return true;
}

bool export_profile(vh_engine* engine, job& current, const fs::path& manifest,
                    const fs::path& output, const std::vector<std::string>& package_ids,
                    std::string& error) {
    std::string manifest_contents;
    if (!read_setting(manifest, manifest_contents, error) || manifest_contents.size() > 2ull * 1024 * 1024 ||
        manifest_contents.find('\0') != std::string::npos) {
        if (error.empty()) error = "Profile manifest is invalid";
        return false;
    }
    const auto partial = output.parent_path() / (output.filename().wstring() + L".part");
    std::error_code ec; fs::create_directories(output.parent_path(), ec); fs::remove(partial, ec);
    void* writer = mz_zip_writer_create();
    if (!writer || mz_zip_writer_open_file(writer, partial.string().c_str(), 0, 0) != MZ_OK) {
        if (writer) mz_zip_writer_delete(&writer); error = "Could not create profile archive"; return false;
    }
    mz_zip_file manifest_info{}; manifest_info.filename = "profile.json";
    manifest_info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;
    if (mz_zip_writer_add_buffer(writer, manifest_contents.data(), static_cast<int32_t>(manifest_contents.size()), &manifest_info) != MZ_OK) {
        error = "Could not write profile manifest";
    }
    std::uint64_t expanded = manifest_contents.size(); std::size_t files = 1;
    for (const auto& id : package_ids) {
        const auto directory = config_directory(engine->config_root, id);
        if (!error.empty() || !fs::is_directory(directory, ec)) { ec.clear(); continue; }
        for (fs::recursive_directory_iterator it(directory, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; ++it) {
            if (current.cancel.load()) { error = "Cancelled"; break; }
            const auto attributes = GetFileAttributesW(it->path().c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                error = "Reparse points cannot be exported: " + it->path().filename().string(); break;
            }
            if (!it->is_regular_file(ec)) continue;
            const auto relative = fs::relative(it->path(), directory, ec).generic_string();
            std::string reason;
            if (ec || !vanahub::is_safe_relative_path(relative, &reason)) { error = "Unsafe settings path"; break; }
            if (!scan_setting_file(it->path(), relative, error)) break;
            const auto size = it->file_size(ec); expanded += size; ++files;
            if (ec || expanded > 256ull * 1024 * 1024 || files > 10000) { error = "Profile settings limits exceeded"; break; }
            const auto archived = "settings/" + id + "/" + relative;
            if (mz_zip_writer_add_file(writer, it->path().string().c_str(), archived.c_str()) != MZ_OK) {
                error = "Could not archive settings file: " + relative; break;
            }
            current.completed = files;
        }
        if (!error.empty()) break;
    }
    mz_zip_writer_close(writer); mz_zip_writer_delete(&writer);
    if (!error.empty()) { fs::remove(partial, ec); return false; }
    if (!MoveFileExW(partial.c_str(), output.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fs::remove(partial, ec); error = "Could not commit profile archive"; return false;
    }
    return true;
}

bool inspect_profile(job& current, const fs::path& archive, const fs::path& staging, std::string& error) {
    std::error_code ec;
    if (!fs::is_regular_file(archive, ec) || fs::file_size(archive, ec) > 64ull * 1024 * 1024) {
        error = "Profile archive is missing or too large"; return false;
    }
    void* reader = mz_zip_reader_create();
    if (!reader || mz_zip_reader_open_file(reader, archive.string().c_str()) != MZ_OK) {
        if (reader) mz_zip_reader_delete(&reader); error = "Unable to open profile archive"; return false;
    }
    std::set<std::string> destinations; std::uint64_t expanded{}; std::size_t entries{}; bool manifest{};
    auto code = mz_zip_reader_goto_first_entry(reader);
    while (code == MZ_OK) {
        mz_zip_file* info{};
        if (mz_zip_reader_entry_get_info(reader, &info) != MZ_OK || !info || !info->filename) { error = "Invalid profile entry"; break; }
        std::string name(info->filename); while (!name.empty() && name.back() == '/') name.pop_back();
        if (name.empty()) { code = mz_zip_reader_goto_next_entry(reader); continue; }
        std::string reason;
        if (!vanahub::is_safe_relative_path(name, &reason) ||
            mz_zip_attrib_is_symlink(info->external_fa, info->version_madeby) == MZ_OK ||
            (info->linkname && *info->linkname) || (info->flag & MZ_ZIP_FLAG_ENCRYPTED) != 0) {
            error = "Unsafe profile archive entry: " + name; break;
        }
        if (info->compression_method != MZ_COMPRESS_METHOD_STORE &&
            info->compression_method != MZ_COMPRESS_METHOD_DEFLATE) {
            error = "Unsupported profile compression method"; break;
        }
        const auto folded = vanahub::ascii_casefold(name);
        if (!destinations.insert(folded).second) { error = "Duplicate or case-colliding profile entry"; break; }
        if (folded == "profile.json") manifest = true;
        else if (!folded.starts_with("settings/")) { error = "Unexpected profile archive entry: " + name; break; }
        expanded += static_cast<std::uint64_t>(info->uncompressed_size); ++entries;
        if (info->uncompressed_size > 32ll * 1024 * 1024) { error = "Profile entry size limit exceeded"; break; }
        if (expanded > 256ull * 1024 * 1024) { error = "Profile total expansion limit exceeded"; break; }
        if (entries > 10000) { error = "Profile entry-count limit exceeded"; break; }
        if (info->compressed_size > 0 && info->uncompressed_size / info->compressed_size > 200) {
            error = "Suspicious profile compression ratio"; break;
        }
        code = mz_zip_reader_goto_next_entry(reader);
    }
    if (error.empty() && !manifest) error = "Profile manifest is missing";
    if (error.empty()) {
        fs::remove_all(staging, ec); fs::create_directories(staging, ec);
        code = mz_zip_reader_goto_first_entry(reader);
        while (code == MZ_OK && !current.cancel.load()) {
            mz_zip_file* info{}; mz_zip_reader_entry_get_info(reader, &info);
            std::string name(info && info->filename ? info->filename : ""); while (!name.empty() && name.back() == '/') name.pop_back();
            if (!name.empty() && mz_zip_reader_entry_is_dir(reader) != MZ_OK) {
                const auto destination = staging / widen(name);
                fs::create_directories(destination.parent_path(), ec);
                if (mz_zip_reader_entry_save_file(reader, destination.string().c_str()) != MZ_OK) { error = "Profile extraction failed"; break; }
                if (vanahub::ascii_casefold(name) == "profile.json") {
                    std::string text;
                    if (!read_setting(destination, text, error) || text.size() > 2ull * 1024 * 1024 || text.find('\0') != std::string::npos)
                        error = "Profile manifest is invalid";
                } else if (!scan_setting_file(destination, name, error)) break;
            }
            code = mz_zip_reader_goto_next_entry(reader);
        }
    }
    mz_zip_reader_close(reader); mz_zip_reader_delete(&reader);
    if (current.cancel.load()) error = "Cancelled";
    if (!error.empty()) fs::remove_all(staging, ec);
    return error.empty();
}

void execute_job(vh_engine* engine, const std::shared_ptr<job>& current, std::string request) {
    const auto operation = json_string(request, "operation");
    const auto package_id = json_string(request, "packageId");
    if (!vanahub::is_safe_package_id(package_id)) { current->finish(VH_INVALID_ARGUMENT, "Invalid packageId"); return; }

    if (operation == "loadRepositoryCache") {
        std::scoped_lock repository_lock(engine->repository_mutex);
        if (!json_bool(request, "requireSignature", false) || engine->builtin_public_key.empty()) {
            current->finish(VH_INVALID_ARGUMENT, "A signed repository cache is required"); return;
        }
        current->update("verifying", "Loading verified repository cache");
        const auto repository_root = engine->cache_root / L"repositories" / widen(package_id);
        std::string path; std::string error;
        if (!load_signed_repository_cache(repository_root, engine->builtin_public_key, path, error)) {
            current->finish(VH_NOT_FOUND, error); return;
        }
        current->finish(VH_OK, path); return;
    }

    if (operation == "fetchRepository") {
        std::scoped_lock repository_lock(engine->repository_mutex);
        const auto url = json_string(request, "url");
        const auto expected_hash = vanahub::ascii_casefold(json_string(request, "sha256"));
        const auto repositories = engine->cache_root / L"repositories";
        const auto repository_root = repositories / widen(package_id);
        const auto destination = repositories / (widen(package_id) + L".json");
        const auto partial = repository_root / L"index.part";
        const auto signature_partial = repository_root / L"index.sig.part";
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
            const auto digest = sha256_file(partial);
            std::string activated;
            if (!valid_sha256(digest) ||
                !activate_signed_repository(repository_root, partial, signature_partial, digest, activated, error)) {
                std::error_code ec; fs::remove(partial, ec); fs::remove(signature_partial, ec);
                current->finish(VH_FILESYSTEM_ERROR, error.empty() ? "Could not activate repository cache" : error); return;
            }
            current->finish(VH_OK, activated); return;
        }
        std::error_code ec; fs::create_directories(repositories, ec);
        if (!MoveFileExW(partial.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            fs::remove(partial, ec); current->finish(VH_FILESYSTEM_ERROR, "Could not activate repository cache"); return;
        }
        std::error_code cleanup_ec; fs::remove(signature_partial, cleanup_ec);
        current->finish(VH_OK, destination.string()); return;
    }

    if (operation == "fetchMedia") {
        std::scoped_lock media_lock(engine->media_mutex);
        const auto url = json_string(request, "url");
        const auto expected_hash = vanahub::ascii_casefold(json_string(request, "sha256"));
        const auto extension = vanahub::ascii_casefold(json_string(request, "extension"));
        const auto allow_local = json_bool(request, "allowLocal", false);
        if (url.empty() || !valid_sha256(expected_hash) ||
            (extension != "jpg" && extension != "jpeg" && extension != "png") ||
            (!allow_local && !url.ends_with(expected_hash + "." + extension))) {
            current->finish(VH_INVALID_ARGUMENT, "Invalid media request"); return;
        }
        const auto media_root = engine->cache_root / L"media";
        const auto destination = media_root / widen(expected_hash + "." + extension);
        if (fs::exists(destination) && sha256_file(destination) == expected_hash) {
            current->finish(VH_OK, destination.generic_string()); return;
        }
        const auto partial = media_root / widen(expected_hash + ".part");
        current->update("downloading", "Downloading catalog media");
        std::string error; std::error_code ec;
        if (!download_file(*current, url, partial, allow_local, false, error)) {
            fs::remove(partial, ec);
            current->finish(current->cancel.load() ? VH_CANCELLED : VH_NETWORK_ERROR, error); return;
        }
        if (fs::file_size(partial, ec) > 8ull * 1024 * 1024 || ec) {
            fs::remove(partial, ec); current->finish(VH_SCAN_REJECTED, "Catalog media exceeds the size limit"); return;
        }
        current->update("hashing", "Verifying catalog media");
        if (sha256_file(partial) != expected_hash) {
            fs::remove(partial, ec); current->finish(VH_HASH_MISMATCH, "Catalog media SHA-256 mismatch"); return;
        }
        fs::create_directories(media_root, ec);
        if (!MoveFileExW(partial.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            fs::remove(partial, ec); current->finish(VH_FILESYSTEM_ERROR, "Could not activate catalog media cache"); return;
        }
        current->finish(VH_OK, destination.generic_string()); return;
    }

    if (operation == "exportProfile") {
        std::scoped_lock mutation(engine->mutation_mutex);
        const auto manifest = fs::path(widen(json_string(request, "manifestPath")));
        const auto output = fs::path(widen(json_string(request, "outputPath")));
        const auto ids = split_ids(json_string(request, "packageIds"));
        if (manifest.empty() || output.empty()) { current->finish(VH_INVALID_ARGUMENT, "Profile export paths are required"); return; }
        current->update("scanning", "Scanning addon settings");
        std::string error;
        if (!export_profile(engine, *current, manifest, output, ids, error)) {
            current->finish(current->cancel.load() ? VH_CANCELLED : VH_SCAN_REJECTED, error); return;
        }
        current->finish(VH_OK, output.generic_string()); return;
    }

    if (operation == "inspectProfile") {
        std::scoped_lock mutation(engine->mutation_mutex);
        const auto input = fs::path(widen(json_string(request, "inputPath")));
        const auto staging = engine->cache_root / L"profile-imports" / std::to_wstring(current->id);
        if (input.empty()) { current->finish(VH_INVALID_ARGUMENT, "Profile import path is required"); return; }
        current->update("inspecting", "Inspecting and scanning profile settings");
        std::string error;
        if (!inspect_profile(*current, input, staging, error)) {
            current->finish(current->cancel.load() ? VH_CANCELLED : VH_SCAN_REJECTED, error); return;
        }
        current->finish(VH_OK, staging.generic_string()); return;
    }

    if (operation == "restoreProfileSettings") {
        std::scoped_lock mutation(engine->mutation_mutex);
        if (package_id == "vanahub") { current->finish(VH_INVALID_ARGUMENT, "VanaHub settings cannot be imported"); return; }
        const auto staging = fs::path(widen(json_string(request, "stagingPath")));
        const auto imports_root = fs::weakly_canonical(engine->cache_root / L"profile-imports");
        const auto canonical_staging = fs::weakly_canonical(staging);
        auto relative_staging = canonical_staging.lexically_relative(imports_root);
        if (staging.empty() || relative_staging.empty() || relative_staging.native().starts_with(L"..")) {
            current->finish(VH_INVALID_ARGUMENT, "Invalid profile staging path"); return;
        }
        const auto source = canonical_staging / L"settings" / widen(package_id);
        if (!fs::is_directory(source)) { current->finish(VH_NOT_FOUND, "No settings were exported for this addon"); return; }
        const auto target = config_directory(engine->config_root, package_id);
        const auto transaction = engine->cache_root / L"transactions" / std::to_wstring(current->id);
        const auto transaction_backup = transaction / L"backup";
        const auto backup = engine->config_root / L"vanahub" / L"backups" /
            std::to_wstring(current->id) / target.filename();
        const auto temporary = engine->config_root / (widen(package_id) + L".vanahub-import");
        std::error_code ec;
        fs::remove_all(temporary, ec); fs::remove_all(transaction, ec); ec.clear();
        fs::copy(source, temporary, fs::copy_options::recursive, ec);
        if (ec) { fs::remove_all(temporary, ec); current->finish(VH_FILESYSTEM_ERROR, "Could not stage imported settings"); return; }
        fs::create_directories(transaction, ec);
        { std::ofstream journal(transaction / L"transaction.json", std::ios::binary | std::ios::trunc);
          journal << "{\"kind\":\"settings\",\"packageId\":\"" << vanahub::json_escape(package_id) << "\"}\n"; }
        current->update("backing_up", "Backing up existing addon settings");
        if (fs::exists(target)) {
            fs::rename(target, transaction_backup, ec);
            if (ec) { fs::remove_all(temporary, ec); fs::remove_all(transaction, ec);
                current->finish(VH_FILESYSTEM_ERROR, "Could not back up existing settings"); return; }
        }
        current->update("committing", "Restoring imported addon settings");
        fs::rename(temporary, target, ec);
        if (ec) {
            std::error_code rollback_ec; fs::remove_all(temporary, rollback_ec);
            if (fs::exists(transaction_backup)) fs::rename(transaction_backup, target, rollback_ec);
            fs::remove_all(transaction, rollback_ec);
            current->finish(VH_FILESYSTEM_ERROR, "Settings restore failed; previous settings were restored"); return;
        }
        if (fs::exists(transaction_backup)) {
            fs::create_directories(backup.parent_path(), ec); fs::rename(transaction_backup, backup, ec);
        }
        fs::remove_all(transaction, ec);
        current->finish(VH_OK, fs::exists(backup) ? backup.generic_string() : std::string{}); return;
    }

    if (operation == "discardProfileImport") {
        std::scoped_lock mutation(engine->mutation_mutex);
        const auto staging = fs::path(widen(json_string(request, "stagingPath")));
        const auto imports_root = fs::weakly_canonical(engine->cache_root / L"profile-imports");
        const auto canonical_staging = fs::weakly_canonical(staging);
        const auto relative = canonical_staging.lexically_relative(imports_root);
        if (staging.empty() || relative.empty() || relative.native().starts_with(L"..")) {
            current->finish(VH_INVALID_ARGUMENT, "Invalid profile staging path"); return;
        }
        std::error_code ec; fs::remove_all(canonical_staging, ec);
        current->finish(ec ? VH_FILESYSTEM_ERROR : VH_OK, ec ? "Could not remove profile staging files" : ""); return;
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
    const auto settings = json_string(config, "configRoot");
    const auto cache = json_string(config, "cacheRoot");
    if (install.empty() || settings.empty() || cache.empty()) return VH_INVALID_ARGUMENT;
    try {
        auto engine = std::make_unique<vh_engine>();
        engine->install_root = fs::path(widen(install));
        engine->config_root = fs::path(widen(settings));
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
            const auto backup = item.path() / L"backup";
            if (json_string(journal, "kind") == "settings") {
                const auto target = config_directory(engine->config_root, package_id);
                if (!fs::exists(target) && fs::exists(backup)) fs::rename(backup, target, ec);
                else if (fs::exists(target) && fs::exists(backup)) {
                    const auto retained = engine->config_root / L"vanahub" / L"backups" /
                        (L"recovered-" + item.path().filename().wstring()) / target.filename();
                    fs::create_directories(retained.parent_path(), ec);
                    if (!ec) fs::rename(backup, retained, ec);
                }
            } else {
                const auto target = engine->install_root / widen(package_id);
                if (!fs::exists(target) && fs::exists(backup)) fs::rename(backup, target, ec);
            }
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
    if (current->worker.joinable()) current->worker.join();
    std::scoped_lock lock(engine->jobs_mutex); engine->jobs.erase(id);
}

void VH_CALL vh_engine_destroy(vh_engine* engine) {
    if (!engine) return; engine->stopping = true;
    std::vector<std::shared_ptr<job>> jobs;
    { std::scoped_lock lock(engine->jobs_mutex); for (auto& [_, value] : engine->jobs) { value->cancel = true; jobs.push_back(value); } }
    jobs.clear(); delete engine;
}
