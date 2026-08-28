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
    for (int attempt = 0; attempt < 500; ++attempt) {
        std::uint32_t required{};
        expect(vh_job_poll(engine, job, nullptr, 0, &required) == VH_BUFFER_TOO_SMALL, "status sizing");
        std::vector<char> buffer(required);
        const auto polled = vh_job_poll(engine, job, buffer.data(), static_cast<std::uint32_t>(buffer.size()), &required);
        if (polled == VH_BUFFER_TOO_SMALL) continue;
        expect(polled == VH_OK, "status polling");
        status.assign(buffer.data());
        if (status.find("\"terminal\":true") != std::string::npos) return status;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return status;
}

std::string status_message(const std::string& status) {
    const auto marker = status.find("\"message\":\"");
    if (marker == std::string::npos) return {};
    const auto start = marker + 11;
    const auto end = status.find('"', start);
    return end == std::string::npos ? std::string{} : status.substr(start, end - start);
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

struct zip_entry {
    std::string name;
    std::string contents;
    std::uint16_t flags{};
    std::uint16_t method{};
    std::uint32_t external_attributes{0100644u << 16};
    std::uint32_t declared_compressed{};
    std::uint32_t declared_uncompressed{};
};

void write_zip(const std::filesystem::path& path, std::vector<zip_entry> entries) {
    std::vector<std::uint8_t> archive;
    std::vector<std::uint32_t> offsets;
    for (auto& entry : entries) {
        offsets.push_back(static_cast<std::uint32_t>(archive.size()));
        const auto checksum = crc32(entry.contents);
        const auto compressed = entry.declared_compressed == 0
            ? static_cast<std::uint32_t>(entry.contents.size()) : entry.declared_compressed;
        const auto uncompressed = entry.declared_uncompressed == 0
            ? static_cast<std::uint32_t>(entry.contents.size()) : entry.declared_uncompressed;
        append_u32(archive, 0x04034b50); append_u16(archive, 20); append_u16(archive, entry.flags); append_u16(archive, entry.method);
        append_u16(archive, 0); append_u16(archive, 0); append_u32(archive, checksum);
        append_u32(archive, compressed); append_u32(archive, uncompressed);
        append_u16(archive, entry.name.size()); append_u16(archive, 0); append_text(archive, entry.name); append_text(archive, entry.contents);
    }
    const auto central_offset = static_cast<std::uint32_t>(archive.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index]; const auto checksum = crc32(entry.contents);
        const auto compressed = entry.declared_compressed == 0
            ? static_cast<std::uint32_t>(entry.contents.size()) : entry.declared_compressed;
        const auto uncompressed = entry.declared_uncompressed == 0
            ? static_cast<std::uint32_t>(entry.contents.size()) : entry.declared_uncompressed;
        append_u32(archive, 0x02014b50); append_u16(archive, 0x0314); append_u16(archive, 20);
        append_u16(archive, entry.flags); append_u16(archive, entry.method); append_u16(archive, 0); append_u16(archive, 0);
        append_u32(archive, checksum); append_u32(archive, compressed); append_u32(archive, uncompressed);
        append_u16(archive, entry.name.size()); append_u16(archive, 0); append_u16(archive, 0); append_u16(archive, 0);
        append_u16(archive, 0); append_u32(archive, entry.external_attributes); append_u32(archive, offsets[index]); append_text(archive, entry.name);
    }
    const auto central_size = static_cast<std::uint32_t>(archive.size()) - central_offset;
    append_u32(archive, 0x06054b50); append_u16(archive, 0); append_u16(archive, 0);
    append_u16(archive, entries.size()); append_u16(archive, entries.size()); append_u32(archive, central_size);
    append_u32(archive, central_offset); append_u16(archive, 0);
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(archive.data()), static_cast<std::streamsize>(archive.size()));
    expect(output.good(), "ZIP fixture write");
}

void write_regular_file_zip(const std::filesystem::path& path) {
    write_zip(path, {{"sample/sample.lua", "return true\n"}});
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

void expect_profile_rejected(vh_engine* engine, const std::filesystem::path& path,
                             std::string_view expected_detail, const char* message) {
    const auto job = vh_job_start(engine,
        ("{\"operation\":\"inspectProfile\",\"packageId\":\"profile-transfer\",\"inputPath\":\"" +
         path.generic_string() + "\"}").c_str());
    expect(job != 0, "hostile profile job creation");
    const auto status = wait_for(engine, job);
    expect(status.find("\"result\":9") != std::string::npos, message);
    if (status.find(expected_detail) == std::string::npos)
        std::cerr << "Fixture " << path.string() << " expected '" << expected_detail << "': " << status << '\n';
    expect(status.find(expected_detail) != std::string::npos, "profile rejection reports the targeted policy");
    vh_job_release(engine, job);
}
}

int main() {
    expect(vh_abi_version() == VH_ABI_VERSION, "ABI version");
    const auto root = std::filesystem::temp_directory_path() / "vanahub-engine-smoke";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    const auto install = (root / "addons").generic_string();
    const auto cache = (root / "cache").generic_string();
    const auto settings = (root / "config" / "addons").generic_string();
    const std::string public_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
    const std::string config = "{\"installRoot\":\"" + install + "\",\"configRoot\":\"" + settings +
        "\",\"cacheRoot\":\"" + cache +
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

    const auto profile_manifest = root / "profile.json";
    const auto profile_archive = root / "portable.vanahub-profile.zip";
    write(profile_manifest, "{\"schemaVersion\":1,\"profile\":{\"name\":\"Portable\",\"addons\":[{\"id\":\"sample\",\"autoLoad\":true,\"settings\":true,\"source\":{\"builtin\":true}}]}}");
    write(root / "config" / "addons" / "Sample" / "settings.lua", "return T{ enabled = true }\n");
    write(root / "config" / "addons" / "Sample" / "theme.uncommon", "accent=blue\n");
    write(root / "config" / "addons" / "Sample" / "notes.lua",
        "-- os.execute('comment only')\nreturn T{ note = \"load('text only')\", load = true }\n");
    const auto export_job = vh_job_start(engine,
        ("{\"operation\":\"exportProfile\",\"packageId\":\"profile-transfer\",\"manifestPath\":\"" +
         profile_manifest.generic_string() + "\",\"outputPath\":\"" + profile_archive.generic_string() +
         "\",\"packageIds\":\"sample\"}").c_str());
    status = wait_for(engine, export_job);
    if (status.find("\"result\":0") == std::string::npos) std::cerr << status << '\n';
    expect(status.find("\"result\":0") != std::string::npos, "profile export succeeds");
    expect(std::filesystem::exists(profile_archive), "profile archive committed");
    vh_job_release(engine, export_job);

    write(root / "config" / "addons" / "Sample" / "settings.lua", "return T{ enabled = false }\n");
    const auto inspect_job = vh_job_start(engine,
        ("{\"operation\":\"inspectProfile\",\"packageId\":\"profile-transfer\",\"inputPath\":\"" +
         profile_archive.generic_string() + "\"}").c_str());
    status = wait_for(engine, inspect_job);
    expect(status.find("\"result\":0") != std::string::npos, "profile import inspection succeeds");
    const auto staging = status_message(status);
    expect(std::filesystem::exists(std::filesystem::path(staging) / "profile.json"), "profile manifest staged");
    vh_job_release(engine, inspect_job);

    const auto catalog_inspect_job = vh_job_start(engine,
        ("{\"operation\":\"inspectCatalogProfile\",\"packageId\":\"profile-transfer\",\"url\":\"file:///" +
         profile_archive.generic_string() + "\",\"sha256\":\"" + sha256(profile_archive) +
         "\",\"compressedSize\":" + std::to_string(std::filesystem::file_size(profile_archive)) +
         ",\"allowLocal\":true,\"githubOnly\":false}").c_str());
    status = wait_for(engine, catalog_inspect_job);
    expect(status.find("\"result\":0") != std::string::npos, "catalog profile download and inspection succeeds");
    const auto catalog_staging = status_message(status);
    expect(std::filesystem::exists(std::filesystem::path(catalog_staging) / "profile.json"),
           "downloaded catalog profile manifest staged");
    vh_job_release(engine, catalog_inspect_job);

    const auto mismatched_catalog_job = vh_job_start(engine,
        ("{\"operation\":\"inspectCatalogProfile\",\"packageId\":\"profile-transfer\",\"url\":\"file:///" +
         profile_archive.generic_string() + "\",\"sha256\":\"" + invalid_digest +
         "\",\"compressedSize\":" + std::to_string(std::filesystem::file_size(profile_archive)) +
         ",\"allowLocal\":true,\"githubOnly\":false}").c_str());
    status = wait_for(engine, mismatched_catalog_job);
    expect(status.find("\"result\":8") != std::string::npos, "catalog profile hash mismatch is rejected");
    vh_job_release(engine, mismatched_catalog_job);

    const auto restore_job = vh_job_start(engine,
        ("{\"operation\":\"restoreProfileSettings\",\"packageId\":\"sample\",\"stagingPath\":\"" +
         staging + "\"}").c_str());
    status = wait_for(engine, restore_job);
    expect(status.find("\"result\":0") != std::string::npos, "profile settings restore succeeds");
    std::ifstream restored(root / "config" / "addons" / "Sample" / "settings.lua");
    const std::string restored_text((std::istreambuf_iterator<char>(restored)), {});
    expect(restored_text.find("enabled = true") != std::string::npos, "imported settings replace local settings");
    vh_job_release(engine, restore_job);

    write(root / "config" / "addons" / "Sample" / "payload.dat", "MZdisguised executable");
    const auto rejected_export = vh_job_start(engine,
        ("{\"operation\":\"exportProfile\",\"packageId\":\"profile-transfer\",\"manifestPath\":\"" +
         profile_manifest.generic_string() + "\",\"outputPath\":\"" + (root / "rejected.zip").generic_string() +
         "\",\"packageIds\":\"sample\"}").c_str());
    status = wait_for(engine, rejected_export);
    expect(status.find("\"result\":9") != std::string::npos, "disguised executable setting rejects export");
    vh_job_release(engine, rejected_export);

    const std::string portable_json =
        "{\"schemaVersion\":1,\"profile\":{\"name\":\"Hostile\",\"addons\":[]}}";
    const auto hostile_root = root / "hostile-profiles";
    auto hostile = hostile_root / "traversal.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/../../escape.lua", "return T{}"}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "profile traversal rejected");
    expect(!std::filesystem::exists(root / "escape.lua"), "profile traversal did not escape staging");

    hostile = hostile_root / "absolute.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"C:/escape.lua", "return T{}"}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "profile absolute path rejected");

    hostile = hostile_root / "device-path.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/CON.txt", "data"}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "profile device path rejected");

    hostile = hostile_root / "alternate-stream.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/theme.txt:stream", "data"}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "profile alternate stream rejected");

    hostile = hostile_root / "case-collision.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/theme.lua", "return T{}"},
        {"settings/sample/THEME.lua", "return T{}"}});
    expect_profile_rejected(engine, hostile, "Duplicate or case-colliding", "profile case collision rejected");

    hostile = hostile_root / "encrypted.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/theme.lua", "return T{}", 1}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "encrypted profile entry rejected");

    hostile = hostile_root / "unsupported-compression.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"settings/sample/theme.lua", "return T{}", 0, 99}});
    expect_profile_rejected(engine, hostile, "Unsupported profile compression", "unsupported profile compression rejected");

    hostile = hostile_root / "symlink.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/link.lua", "target.lua", 0, 0, 0120777u << 16}});
    expect_profile_rejected(engine, hostile, "Unsafe profile archive entry", "profile symlink rejected");

    hostile = hostile_root / "nested.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/theme.data", std::string("PK\x03\x04payload", 11)}});
    expect_profile_rejected(engine, hostile, "Nested archives cannot be imported", "nested archive setting rejected");

    hostile = hostile_root / "unsafe-lua.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/theme.lua", "return T{}\nos.execute('bad')"}});
    expect_profile_rejected(engine, hostile, "Prohibited symbol: os", "unsafe imported Lua setting rejected");

    hostile = hostile_root / "binary.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/theme.data", std::string("data\0payload", 12)}});
    expect_profile_rejected(engine, hostile, "Unrecognized binary settings", "unknown imported binary setting rejected");

    hostile = hostile_root / "entry-too-large.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/theme.txt", "x", 0, 0, 0100644u << 16, 1, 32u * 1024u * 1024u + 1u}});
    expect_profile_rejected(engine, hostile, "Profile entry size limit exceeded", "profile per-entry size limit enforced");

    hostile = hostile_root / "expansion-too-large.zip";
    std::vector<zip_entry> expanded_entries{{"profile.json", portable_json}};
    for (int index = 0; index < 9; ++index) expanded_entries.push_back({
        "settings/sample/large" + std::to_string(index) + ".txt", "x", 0, 0,
        0100644u << 16, 1024u * 1024u, 31u * 1024u * 1024u});
    write_zip(hostile, std::move(expanded_entries));
    expect_profile_rejected(engine, hostile, "Profile total expansion limit exceeded", "profile total expansion limit enforced");

    hostile = hostile_root / "compression-ratio.zip";
    write_zip(hostile, {{"profile.json", portable_json},
        {"settings/sample/theme.txt", "x", 0, 0, 0100644u << 16, 1, 201}});
    expect_profile_rejected(engine, hostile, "Suspicious profile compression ratio", "profile compression ratio limit enforced");

    hostile = hostile_root / "too-many-entries.zip";
    std::vector<zip_entry> many_entries; many_entries.reserve(10001);
    many_entries.push_back({"profile.json", portable_json});
    for (int index = 0; index < 10000; ++index)
        many_entries.push_back({"settings/sample/file" + std::to_string(index), ""});
    write_zip(hostile, std::move(many_entries));
    expect_profile_rejected(engine, hostile, "Profile entry-count limit exceeded", "profile entry-count limit enforced");

    hostile = hostile_root / "archive-too-large.zip";
    write_zip(hostile, {{"profile.json", portable_json}});
    std::filesystem::resize_file(hostile, 64ull * 1024 * 1024 + 1, ec);
    expect(!ec, "oversized profile fixture created");
    expect_profile_rejected(engine, hostile, "Profile archive is missing or too large", "profile compressed-size limit enforced");

    hostile = hostile_root / "missing-manifest.zip";
    write_zip(hostile, {{"settings/sample/theme.lua", "return T{}"}});
    expect_profile_rejected(engine, hostile, "Profile manifest is missing", "profile manifest is required");

    hostile = hostile_root / "unexpected-root.zip";
    write_zip(hostile, {{"profile.json", portable_json}, {"readme.txt", "unexpected"}});
    expect_profile_rejected(engine, hostile, "Unexpected profile archive entry", "unexpected profile root rejected");

    hostile = hostile_root / "corrupt.zip";
    write(hostile, "not a zip archive");
    expect_profile_rejected(engine, hostile, "Unable to open profile archive", "corrupt profile archive rejected");

    const auto media_digest = sha256(archive);
    const auto media_job = vh_job_start(engine,
        ("{\"operation\":\"fetchMedia\",\"packageId\":\"sample\",\"url\":\"file:///" +
         archive.generic_string() + "\",\"sha256\":\"" + media_digest +
         "\",\"extension\":\"jpg\",\"allowLocal\":true}").c_str());
    expect(media_job != 0, "media job creation");
    status = wait_for(engine, media_job);
    expect(status.find("\"result\":0") != std::string::npos, "content-addressed media cached");
    expect(std::filesystem::exists(root / "cache" / "media" / (media_digest + ".jpg")), "media cache written");
    vh_job_release(engine, media_job);

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
