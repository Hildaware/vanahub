#include "xirepo/core.hpp"

#include <cstdlib>
#include <iostream>

namespace {
void expect(bool value, const char* message) {
    if (!value) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}
}

int main() {
    expect(xirepo::is_safe_package_id("sample-addon"), "valid package id");
    expect(!xirepo::is_safe_package_id("Sample"), "uppercase package id rejected");
    expect(xirepo::is_safe_relative_path("sample/data/items.json"), "normal relative path");
    expect(!xirepo::is_safe_relative_path("../escape.lua"), "traversal rejected");
    expect(!xirepo::is_safe_relative_path("C:/escape.lua"), "drive rejected");
    expect(!xirepo::is_safe_relative_path("sample/CON.txt"), "device rejected");
    expect(!xirepo::is_safe_relative_path("sample/file.lua:stream"), "ADS rejected");
    expect(xirepo::is_allowed_extension("sample/data.json"), "data extension accepted");
    expect(!xirepo::is_allowed_extension("sample/helper.dll"), "native extension rejected");
    expect(xirepo::scan_lua("local imgui = require('imgui')", "sample.lua").empty(), "safe Lua accepted");
    expect(xirepo::scan_lua("local preload = true", "sample.lua").empty(), "blocked names use identifier boundaries");
    expect(!xirepo::scan_lua("os.execute('bad')", "sample.lua").empty(), "process execution rejected");
    expect(!xirepo::scan_lua("load('bad')", "sample.lua").empty(), "dynamic loading rejected");
    return 0;
}
