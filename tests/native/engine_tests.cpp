#include "xirepo/api.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
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
}

int main() {
    expect(xr_abi_version() == XR_ABI_VERSION, "ABI version");
    const auto root = std::filesystem::temp_directory_path() / "xirepo-engine-smoke";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    const auto install = (root / "addons").generic_string();
    const auto cache = (root / "cache").generic_string();
    const std::string config = "{\"installRoot\":\"" + install + "\",\"cacheRoot\":\"" + cache + "\"}";

    xr_engine* engine{};
    expect(xr_engine_create(config.c_str(), &engine) == XR_OK && engine != nullptr, "engine creation");
    expect(xr_engine_recover(engine) == XR_OK, "empty recovery");
    const auto job = xr_job_start(engine, "{\"operation\":\"unknown\",\"packageId\":\"sample\"}");
    expect(job != 0, "job creation");

    std::string status;
    for (int attempt = 0; attempt < 100; ++attempt) {
        std::uint32_t required{};
        expect(xr_job_poll(engine, job, nullptr, 0, &required) == XR_BUFFER_TOO_SMALL, "status sizing");
        std::vector<char> buffer(required);
        expect(xr_job_poll(engine, job, buffer.data(), required, &required) == XR_OK, "status polling");
        status.assign(buffer.data());
        if (status.find("\"terminal\":true") != std::string::npos) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    expect(status.find("\"terminal\":true") != std::string::npos, "job completes");
    expect(status.find("\"result\":1") != std::string::npos, "unsupported operation is rejected");
    xr_job_release(engine, job);
    xr_engine_destroy(engine);
    std::filesystem::remove_all(root, ec);
    return 0;
}
