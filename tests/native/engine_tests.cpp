#include "vanahub/api.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
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
