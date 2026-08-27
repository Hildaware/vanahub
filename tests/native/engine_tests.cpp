#include "vanahub/api.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {
void expect(bool value, const char* message) {
    if (!value) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}

std::string wait_for(vh_engine* engine, vh_job_id job) {
    std::string status;
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::uint32_t required{};
        expect(vh_job_poll(engine, job, nullptr, 0, &required) == VH_BUFFER_TOO_SMALL, "status sizing");
        std::vector<char> buffer(required);
        expect(vh_job_poll(engine, job, buffer.data(), required, &required) == VH_OK, "status polling");
        status.assign(buffer.data());
        if (status.find("\"terminal\":true") != std::string::npos) return status;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return status;
}

void write(const std::filesystem::path& path, const std::string& value) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << value;
    expect(output.good(), "fixture write");
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    append_u16(output, static_cast<std::uint16_t>(value));
    append_u16(output, static_cast<std::uint16_t>(value >> 16));
}

std::uint32_t crc32(std::string_view value) {
    std::uint32_t crc = 0xffffffffu;
    for (const auto byte : value) {
        crc ^= static_cast<std::uint8_t>(byte);
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

void append_text(std::vector<std::uint8_t>& output, std::string_view value) {
    output.insert(output.end(), value.begin(), value.end());
}

void write_regular_file_zip(const std::filesystem::path& path) {
    constexpr std::string_view name = "sample/sample.lua";
    constexpr std::string_view contents = "return true\n";
    const auto checksum = crc32(contents);
    std::vector<std::uint8_t> archive;
    append_u32(archive, 0x04034b50); append_u16(archive, 20); append_u16(archive, 0); append_u16(archive, 0);
    append_u16(archive, 0); append_u16(archive, 0); append_u32(archive, checksum);
    append_u32(archive, contents.size()); append_u32(archive, contents.size());
    append_u16(archive, name.size()); append_u16(archive, 0); append_text(archive, name); append_text(archive, contents);
    const auto central_offset = static_cast<std::uint32_t>(archive.size());
    append_u32(archive, 0x02014b50); append_u16(archive, 0x0314); append_u16(archive, 20);
    append_u16(archive, 0); append_u16(archive, 0); append_u16(archive, 0); append_u16(archive, 0);
    append_u32(archive, checksum); append_u32(archive, contents.size()); append_u32(archive, contents.size());
    append_u16(archive, name.size()); append_u16(archive, 0); append_u16(archive, 0); append_u16(archive, 0);
    append_u16(archive, 0); append_u32(archive, 0100644u << 16); append_u32(archive, 0); append_text(archive, name);
    const auto central_size = static_cast<std::uint32_t>(archive.size()) - central_offset;
    append_u32(archive, 0x06054b50); append_u16(archive, 0); append_u16(archive, 0);
    append_u16(archive, 1); append_u16(archive, 1); append_u32(archive, central_size);
    append_u32(archive, central_offset); append_u16(archive, 0);
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(archive.data()), static_cast<std::streamsize>(archive.size()));
    expect(output.good(), "ZIP fixture write");
}

std::string sha256(const std::filesystem::path& path) {
    BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE hash{}; DWORD object_size{}, received{};
    expect(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "SHA-256 provider");
    expect(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size), &received, 0) >= 0, "SHA-256 object size");
    std::vector<std::uint8_t> object(object_size); std::array<std::uint8_t, 32> digest{};
    expect(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) >= 0, "SHA-256 hash");
    std::ifstream input(path, std::ios::binary); std::array<char, 4096> buffer{};
    while (input) {
        input.read(buffer.data(), buffer.size());
        if (input.gcount() > 0) expect(BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
            static_cast<ULONG>(input.gcount()), 0) >= 0, "SHA-256 data");
    }
    expect(input.eof() && BCryptFinishHash(hash, digest.data(), digest.size(), 0) >= 0, "SHA-256 finish");
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    std::ostringstream output;
    for (const auto byte : digest) output << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    return output.str();
}
}

int main() {
    expect(vh_abi_version() == VH_ABI_VERSION, "ABI version");
    const auto root = std::filesystem::temp_directory_path() / "vanahub-engine-smoke";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    const auto install = (root / "addons").generic_string();
    const auto cache = (root / "cache").generic_string();
    const std::string public_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
    const std::string config = "{\"installRoot\":\"" + install + "\",\"cacheRoot\":\"" + cache +
        "\",\"builtinPublicKey\":\"" + public_key + "\"}";

    vh_engine* engine{};
    expect(vh_engine_create(config.c_str(), &engine) == VH_OK && engine != nullptr, "engine creation");
    expect(vh_engine_recover(engine) == VH_OK, "empty recovery");
    const auto job = vh_job_start(engine, "{\"operation\":\"unknown\",\"packageId\":\"sample\"}");
    expect(job != 0, "job creation");

    auto status = wait_for(engine, job);
    expect(status.find("\"terminal\":true") != std::string::npos, "job completes");
    expect(status.find("\"result\":1") != std::string::npos, "unsupported operation is rejected");
    vh_job_release(engine, job);

    const std::string valid_digest = "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1";
    const std::string invalid_digest = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
    const auto repository = root / "cache" / "repositories" / "builtin";
    const auto valid = repository / "generations" / valid_digest;
    const auto invalid = repository / "generations" / invalid_digest;
    const std::string signature =
        "{\"algorithm\":\"Ed25519\",\"keyId\":\"test\",\"signature\":"
        "\"kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA==\"}";
    write(valid / "index.json", "r");
    write(valid / "index.json.sig", signature);
    write(invalid / "index.json", "x");
    write(invalid / "index.json.sig", signature);
    write(repository / "current", invalid_digest + "\n");

    const auto cached = vh_job_start(engine,
        "{\"operation\":\"loadRepositoryCache\",\"packageId\":\"builtin\",\"requireSignature\":true}");
    expect(cached != 0, "cache load job creation");
    status = wait_for(engine, cached);
    expect(status.find("\"result\":0") != std::string::npos, "previous signed cache generation is loaded");
    expect(status.find(valid_digest) != std::string::npos, "cache result identifies verified generation");
    vh_job_release(engine, cached);
    std::ifstream pointer(repository / "current");
    std::string active; pointer >> active;
    expect(active == valid_digest, "cache pointer recovers to verified generation");

    const auto archive = root / "regular-file.zip";
    write_regular_file_zip(archive);
    const auto install_job = vh_job_start(engine,
        ("{\"operation\":\"install\",\"packageId\":\"sample\",\"url\":\"file:///" +
         archive.generic_string() + "\",\"sha256\":\"" + sha256(archive) +
         "\",\"archiveRoot\":\"sample\",\"entrypoint\":\"sample.lua\","
         "\"allowElevated\":false,\"allowLocal\":true,\"githubOnly\":false}").c_str());
    expect(install_job != 0, "install job creation");
    status = wait_for(engine, install_job);
    expect(status.find("\"result\":0") != std::string::npos, "regular ZIP entry is not treated as a symlink");
    expect(std::filesystem::exists(root / "addons" / "sample" / "sample.lua"), "addon entrypoint installed");
    vh_job_release(engine, install_job);

    write(valid / "index.json", "tampered");
    const auto tampered = vh_job_start(engine,
        "{\"operation\":\"loadRepositoryCache\",\"packageId\":\"builtin\",\"requireSignature\":true}");
    status = wait_for(engine, tampered);
    expect(status.find("\"result\":3") != std::string::npos, "tampered cache is rejected");
    vh_job_release(engine, tampered);
    vh_engine_destroy(engine);
    std::filesystem::remove_all(root, ec);
    return 0;
}
