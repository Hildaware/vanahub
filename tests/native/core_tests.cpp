#include "vanahub/core.hpp"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {
void expect(bool value, const char* message) {
    if (!value) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}

std::string bytes(std::initializer_list<unsigned int> values) {
    std::string result;
    for (const auto value : values) result.push_back(static_cast<char>(value));
    return result;
}

void expect_setting_allowed(std::string_view contents, std::string_view path, const char* message) {
    expect(vanahub::scan_setting(contents, path).empty(), message);
}

void expect_setting_rejected(std::string_view contents, std::string_view path, const char* message) {
    expect(!vanahub::scan_setting(contents, path).empty(), message);
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
    expect_setting_allowed("", "settings.unknown", "empty settings accepted");
    expect_setting_allowed("{\"theme\":\"dark\"}", "settings.custom", "unknown text settings accepted");
    expect_setting_allowed("name=caf\xc3\xa9\n", "settings.conf", "UTF-8 text settings accepted");
    expect_setting_allowed(std::string("name=caf") + bytes({0xe9}) + "\n", "settings.ansi",
        "legacy ANSI text settings accepted");
    expect_setting_allowed("one\ttwo\r\nthree\f", "settings.text", "normal text controls accepted");
    expect_setting_rejected(std::string("one") + bytes({0x01}) + "two", "settings.text",
        "unexpected control bytes rejected");
    expect_setting_rejected(std::string("data\0payload", 12), "settings.bin", "NUL binary rejected");

    const std::vector<std::string> blocked_extensions{
        "application", "bash", "bat", "chm", "cmd", "com", "cpl", "dll", "drv", "exe", "fish",
        "gadget", "hta", "jar", "js", "jse", "lnk", "msi", "msp", "php", "pif", "pl", "ps1",
        "py", "rb", "reg", "scr", "sh", "sys", "vbe", "vbs", "wsf", "wsh", "zsh"
    };
    for (const auto& extension : blocked_extensions) {
        expect_setting_rejected("plain text", "settings." + extension, "executable extension rejected");
        std::string upper = extension;
        for (auto& value : upper) value = static_cast<char>(std::toupper(static_cast<unsigned char>(value)));
        expect_setting_rejected("plain text", "SETTINGS." + upper, "executable extension is case-insensitive");
    }

    const std::vector<std::string> executable_headers{
        "MZpayload", bytes({0x7f, 'E', 'L', 'F'}), bytes({0xfe, 0xed, 0xfa, 0xce}),
        bytes({0xce, 0xfa, 0xed, 0xfe}), bytes({0xfe, 0xed, 0xfa, 0xcf}),
        bytes({0xcf, 0xfa, 0xed, 0xfe}), bytes({0xca, 0xfe, 0xba, 0xbe}), bytes({0x00, 'a', 's', 'm'})
    };
    for (const auto& header : executable_headers)
        expect_setting_rejected(header + "payload", "settings.data", "executable magic rejected regardless of extension");

    const std::vector<std::string> archive_headers{
        bytes({'P', 'K', 0x03, 0x04}), bytes({'P', 'K', 0x05, 0x06}), bytes({'P', 'K', 0x07, 0x08}),
        "Rar!", bytes({'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}), bytes({0x1f, 0x8b}), "BZh9",
        bytes({0xfd, '7', 'z', 'X', 'Z', 0x00}), bytes({0x28, 0xb5, 0x2f, 0xfd})
    };
    for (const auto& header : archive_headers)
        expect_setting_rejected(header + "payload", "settings.data", "nested archive magic rejected");

    expect_setting_rejected("#!/bin/sh\nexit 0\n", "settings.txt", "script shebang rejected");
    expect_setting_rejected("\xef\xbb\xbf#!/bin/sh\n", "settings.txt", "BOM-prefixed shebang rejected");
    expect_setting_allowed("prefix #!/bin/sh is documentation\n", "settings.txt", "non-leading shebang text accepted");

    expect_setting_allowed("return T{ enabled = true }", "settings.lua", "serialized Lua settings accepted");
    expect_setting_allowed("return T{ note = \"os.execute('text')\", load = true }", "settings.LUA",
        "dangerous words inside Lua strings and data keys are accepted");
    expect_setting_allowed("-- os.execute('comment')\nreturn T{}", "settings.lua",
        "dangerous words inside line comments are accepted");
    expect_setting_allowed("--[=[ load('comment') ]=]\nreturn T{ note = [=[ffi]=] }", "settings.lua",
        "dangerous words inside long comments and strings are accepted");
    expect_setting_rejected("return T{}\nos.execute('bad')", "settings.lua", "unsafe Lua code rejected");
    expect_setting_rejected("local runner = os; runner.execute('bad')", "settings.lua", "Lua aliases rejected");
    expect_setting_rejected("require('anything')", "settings.lua", "Lua settings module loads rejected");
    expect_setting_rejected(std::string(4001, 'a'), "settings.lua", "obfuscated Lua line rejected");
    expect_setting_rejected("return T{ note = \"unterminated }", "settings.lua", "unterminated Lua string rejected");
    expect_setting_rejected("return T{ note = [=[unterminated }", "settings.lua", "unterminated Lua long string rejected");
    expect_setting_rejected("return T{ enabled = true", "settings.lua", "unbalanced Lua table rejected");
    expect_setting_allowed("return T{ preload = true }", "settings.lua", "blocked substrings respect identifiers");

    std::string png(24, '\0');
    png.replace(0, 8, bytes({0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}));
    png.replace(12, 4, "IHDR");
    const auto jpeg = bytes({0xff, 0xd8, 0xff, 0xe0}) + std::string("payload") + bytes({0xff, 0xd9});
    std::string dds(128, '\0'); dds.replace(0, 4, "DDS ");
    std::string wav = "RIFF" + std::string(4, '\0') + "WAVE";
    expect_setting_allowed(png, "theme.uncommon", "PNG accepted by content without extension");
    expect_setting_allowed(jpeg, "theme.uncommon", "JPEG accepted by content without extension");
    expect_setting_allowed(dds, "theme.uncommon", "DDS accepted by content without extension");
    expect_setting_allowed(wav, "theme.uncommon", "WAV accepted by content without extension");
    expect_setting_rejected(bytes({0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}), "theme.png",
        "truncated PNG rejected");
    expect_setting_rejected(bytes({0xff, 0xd8, 0xff, 0xe0}), "theme.jpg", "truncated JPEG rejected");
    expect_setting_rejected("DDS short", "theme.dds", "truncated DDS rejected");
    expect_setting_rejected("RIFF1234NOPE", "theme.wav", "malformed WAV rejected");
    expect_setting_rejected(bytes({'P', 'K', 0x03}), "almost.zip", "truncated magic falls through to binary rejection");

    std::uint32_t random = 0x5eed1234u;
    for (int iteration = 0; iteration < 1000; ++iteration) {
        random = random * 1664525u + 1013904223u;
        std::string sample(random % 1025u, '\0');
        for (auto& value : sample) {
            random = random * 1664525u + 1013904223u;
            value = static_cast<char>(random >> 24);
        }
        const auto first = vanahub::scan_setting(sample, "fuzz.uncommon");
        const auto second = vanahub::scan_setting(sample, "fuzz.uncommon");
        expect(first.size() == second.size(), "arbitrary-byte scan is deterministic");
        if (!first.empty()) expect(first.front().rule_id == second.front().rule_id,
            "arbitrary-byte rejection rule is deterministic");
        expect_setting_rejected(sample, "fuzz.EXE", "blocked extension dominates arbitrary content");
        const auto lua_result = vanahub::scan_setting(sample, "fuzz.lua");
        (void)lua_result;
    }
    return 0;
}
