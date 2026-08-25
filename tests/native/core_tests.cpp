#include "vanahub/core.hpp"

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
    expect(vanahub::is_safe_package_id("sample-addon"), "valid package id");
    expect(!vanahub::is_safe_package_id("Sample"), "uppercase package id rejected");
    expect(vanahub::is_safe_relative_path("sample/data/items.json"), "normal relative path");
    expect(!vanahub::is_safe_relative_path("../escape.lua"), "traversal rejected");
    expect(!vanahub::is_safe_relative_path("C:/escape.lua"), "drive rejected");
    expect(!vanahub::is_safe_relative_path("sample/CON.txt"), "device rejected");
    expect(!vanahub::is_safe_relative_path("sample/file.lua:stream"), "ADS rejected");
    expect(vanahub::is_allowed_extension("sample/data.json"), "data extension accepted");
    expect(!vanahub::is_allowed_extension("sample/helper.dll"), "native extension rejected");
    expect(vanahub::scan_lua("local imgui = require('imgui')", "sample.lua").empty(), "safe Lua accepted");
    expect(vanahub::scan_lua("local preload = true", "sample.lua").empty(), "blocked names use identifier boundaries");
    expect(!vanahub::scan_lua("os.execute('bad')", "sample.lua").empty(), "process execution rejected");
    expect(!vanahub::scan_lua("local runner = os; runner.execute('bad')", "sample.lua").empty(), "standard-library aliases rejected");
    expect(!vanahub::scan_lua("load('bad')", "sample.lua").empty(), "dynamic loading rejected");
    return 0;
}
