#include "vanahub/core.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <regex>
#include <set>
#include <span>

namespace vanahub {
namespace {

constexpr std::array<std::string_view, 33> blocked_symbols{
    "ffi", "socket", "ssl.https", "os", "io", "package", "os.execute", "io.popen", "package.loadlib",
    "loadstring", "load", "loadfile", "dofile", "getfenv", "setfenv", "_env", "string.dump", "debug", "ashita.memory.write", "injectpacket",
    "queuecommand", "createprocess", "shellexecute", "winexec", "loadlibrary",
    "regsetvalue", "urldownloadtofile", "winhttpopen", "internetopen",
    "deletefile", "removeDirectory", "virtualprotect", "writeprocessmemory"
};

bool is_device(std::string value) {
    while (!value.empty() && (value.back() == ' ' || value.back() == '.')) value.pop_back();
    const auto dot = value.find('.');
    if (dot != std::string::npos) value.resize(dot);
    value = ascii_casefold(value);
    static const std::set<std::string> fixed{"con", "prn", "aux", "nul", "clock$"};
    if (fixed.contains(value)) return true;
    if (value.size() == 4 && (value.starts_with("com") || value.starts_with("lpt")) && value[3] >= '1' && value[3] <= '9') return true;
    return false;
}

int lua_long_bracket_level(std::string_view source, std::size_t position) {
    if (position >= source.size() || source[position] != '[') return -1;
    std::size_t cursor = position + 1;
    while (cursor < source.size() && source[cursor] == '=') ++cursor;
    return cursor < source.size() && source[cursor] == '['
        ? static_cast<int>(cursor - position - 1) : -1;
}

std::string mask_lua_literals(std::string_view source, bool& malformed) {
    malformed = false;
    std::string result(source);
    const auto mask = [&](std::size_t begin, std::size_t end) {
        for (auto index = begin; index < end && index < result.size(); ++index)
            if (result[index] != '\n' && result[index] != '\r') result[index] = ' ';
    };
    std::size_t index{};
    while (index < source.size()) {
        if ((source[index] == '\'' || source[index] == '"')) {
            const auto quote = source[index]; const auto begin = index++; bool closed{};
            while (index < source.size()) {
                if (source[index] == '\\' && index + 1 < source.size()) { index += 2; continue; }
                if (source[index++] == quote) { closed = true; break; }
            }
            if (!closed) malformed = true;
            mask(begin, index); continue;
        }
        if (source[index] == '-' && index + 1 < source.size() && source[index + 1] == '-') {
            const auto begin = index; index += 2;
            const auto level = lua_long_bracket_level(source, index);
            if (level < 0) {
                while (index < source.size() && source[index] != '\n') ++index;
            } else {
                index += static_cast<std::size_t>(level) + 2;
                const auto close = "]" + std::string(static_cast<std::size_t>(level), '=') + "]";
                const auto end = source.find(close, index);
                if (end == std::string_view::npos) malformed = true;
                index = end == std::string_view::npos ? source.size() : end + close.size();
            }
            mask(begin, index); continue;
        }
        const auto level = lua_long_bracket_level(source, index);
        if (level >= 0) {
            const auto begin = index; index += static_cast<std::size_t>(level) + 2;
            const auto close = "]" + std::string(static_cast<std::size_t>(level), '=') + "]";
            const auto end = source.find(close, index);
            if (end == std::string_view::npos) malformed = true;
            index = end == std::string_view::npos ? source.size() : end + close.size();
            mask(begin, index); continue;
        }
        ++index;
    }
    return result;
}

bool balanced_lua_delimiters(std::string_view source) {
    std::vector<char> stack;
    for (const auto value : source) {
        if (value == '(' || value == '{' || value == '[') stack.push_back(value);
        else if (value == ')' || value == '}' || value == ']') {
            if (stack.empty()) return false;
            const auto open = stack.back(); stack.pop_back();
            if ((value == ')' && open != '(') || (value == '}' && open != '{') ||
                (value == ']' && open != '[')) return false;
        }
    }
    return stack.empty();
}

void mask_lua_table_keys(std::string& source) {
    std::size_t index{};
    while (index < source.size()) {
        const auto identifier = [](unsigned char value) { return std::isalnum(value) != 0 || value == '_'; };
        if (!(std::isalpha(static_cast<unsigned char>(source[index])) || source[index] == '_')) { ++index; continue; }
        const auto begin = index++;
        while (index < source.size() && identifier(static_cast<unsigned char>(source[index]))) ++index;
        auto after = index;
        while (after < source.size() && std::isspace(static_cast<unsigned char>(source[after]))) ++after;
        auto before = begin;
        while (before > 0 && std::isspace(static_cast<unsigned char>(source[before - 1]))) --before;
        if (after < source.size() && source[after] == '=' && before > 0 &&
            (source[before - 1] == '{' || source[before - 1] == ',')) {
            for (auto cursor = begin; cursor < index; ++cursor) source[cursor] = ' ';
        }
    }
}

std::uint32_t line_at(std::string_view text, std::size_t offset) {
    return 1u + static_cast<std::uint32_t>(std::count(text.begin(), text.begin() + static_cast<std::ptrdiff_t>(offset), '\n'));
}

} // namespace

std::string ascii_casefold(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

bool is_safe_package_id(std::string_view value) {
    if (value.size() < 2 || value.size() > 64) return false;
    if (!(value.front() >= 'a' && value.front() <= 'z') && !(value.front() >= '0' && value.front() <= '9')) return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

bool is_allowed_extension(std::string_view value) {
    const auto slash = value.find_last_of("/\\");
    const auto dot = value.find_last_of('.');
    const auto extension = dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)
        ? std::string{} : ascii_casefold(value.substr(dot));
    static const std::set<std::string> allowed{
        "", ".lua", ".json", ".ini", ".xml", ".txt", ".md", ".png", ".jpg", ".jpeg",
        ".dds", ".wav", ".psd", ".ps1", ".sh", ".yml", ".yaml", ".gitmodules", ".gitattributes",
        ".gitignore", ".bmp"
    };
    return allowed.contains(extension);
}

bool is_safe_relative_path(std::string_view value, std::string* reason) {
    auto fail = [&](std::string_view why) { if (reason) *reason = why; return false; };
    if (value.empty()) return fail("path is empty");
    if (value.front() == '/' || value.front() == '\\') return fail("absolute or UNC path");
    if (value.size() >= 2 && std::isalpha(static_cast<unsigned char>(value[0])) && value[1] == ':') return fail("drive path");
    if (value.find('\\') != std::string_view::npos || value.find('\0') != std::string_view::npos) return fail("backslash or NUL");
    std::size_t start = 0;
    while (start <= value.size()) {
        auto end = value.find('/', start);
        if (end == std::string_view::npos) end = value.size();
        const auto part = value.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") return fail("empty, dot, or traversal segment");
        if (part.find(':') != std::string_view::npos) return fail("alternate data stream");
        if (part.back() == ' ' || part.back() == '.') return fail("ambiguous trailing character");
        if (is_device(std::string(part))) return fail("Windows device path");
        if (end == value.size()) break;
        start = end + 1;
    }
    return true;
}

std::vector<finding> scan_lua(std::string_view source, std::string_view path) {
    std::vector<finding> result;
    const auto folded = ascii_casefold(source);
    for (const auto symbol : blocked_symbols) {
        const auto needle = ascii_casefold(symbol);
        auto offset = folded.find(needle);
        while (offset != std::string::npos) {
            const auto identifier = [](unsigned char c) { return std::isalnum(c) != 0 || c == '_'; };
            const auto left_ok = offset == 0 || !identifier(static_cast<unsigned char>(folded[offset - 1]));
            const auto right = offset + needle.size();
            const auto right_ok = right == folded.size() || !identifier(static_cast<unsigned char>(folded[right]));
            if (left_ok && right_ok) {
            result.push_back({"lua.blocked-symbol", severity::error,
                "Prohibited symbol: " + std::string(symbol), std::string(path), line_at(source, offset), "elevated"});
                break;
            }
            offset = folded.find(needle, offset + 1);
        }
    }
    if (folded.find("_g") != std::string::npos) {
        result.push_back({"lua.environment-manipulation", severity::error,
            "Global environment access requires review", std::string(path), 0, "dynamic-code"});
    }
    std::size_t start = 0;
    while (start < source.size()) {
        const auto end = source.find('\n', start);
        const auto length = (end == std::string_view::npos ? source.size() : end) - start;
        if (length > 4000) {
            result.push_back({"lua.obfuscated-line", severity::error,
                "Source contains an excessively long line", std::string(path), line_at(source, start), "obfuscation"});
            break;
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return result;
}

std::vector<finding> scan_setting(std::string_view contents, std::string_view path) {
    const auto folded_path = ascii_casefold(path);
    const auto dot = folded_path.find_last_of('.');
    const auto extension = dot == std::string::npos ? std::string{} : folded_path.substr(dot);
    static const std::set<std::string> executable_extensions{
        ".application", ".bash", ".bat", ".chm", ".cmd", ".com", ".cpl", ".dll", ".drv",
        ".exe", ".fish", ".gadget", ".hta", ".jar", ".js", ".jse", ".lnk", ".msi", ".msp",
        ".php", ".pif", ".pl", ".ps1", ".py", ".rb", ".reg", ".scr", ".sh", ".sys", ".vbe",
        ".vbs", ".wsf", ".wsh", ".zsh"
    };
    if (executable_extensions.contains(extension)) {
        return {{"settings.executable-extension", severity::error,
            "Executable or general-purpose script files cannot be imported", std::string(path), 0, "executable-settings"}};
    }

    const auto starts = [&](std::initializer_list<unsigned char> bytes) {
        if (contents.size() < bytes.size()) return false;
        std::size_t index{};
        for (const auto byte : bytes) if (static_cast<unsigned char>(contents[index++]) != byte) return false;
        return true;
    };
    const auto executable_magic = starts({'M', 'Z'}) || starts({0x7f, 'E', 'L', 'F'}) ||
        starts({0xfe, 0xed, 0xfa, 0xce}) || starts({0xce, 0xfa, 0xed, 0xfe}) ||
        starts({0xfe, 0xed, 0xfa, 0xcf}) || starts({0xcf, 0xfa, 0xed, 0xfe}) ||
        starts({0xca, 0xfe, 0xba, 0xbe}) || starts({0x00, 'a', 's', 'm'});
    const auto archive_magic = starts({'P', 'K', 0x03, 0x04}) || starts({'P', 'K', 0x05, 0x06}) ||
        starts({'P', 'K', 0x07, 0x08}) || starts({'R', 'a', 'r', '!'}) ||
        starts({'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}) || starts({0x1f, 0x8b}) ||
        starts({'B', 'Z', 'h'}) || starts({0xfd, '7', 'z', 'X', 'Z', 0x00}) ||
        starts({0x28, 0xb5, 0x2f, 0xfd});
    if (executable_magic || archive_magic) {
        return {{executable_magic ? "settings.executable-content" : "settings.nested-archive",
            severity::error, executable_magic ? "Executable content cannot be imported"
                                               : "Nested archives cannot be imported",
            std::string(path), 0, executable_magic ? "executable-settings" : "archive-settings"}};
    }
    if (contents.starts_with("#!") || contents.starts_with("\xef\xbb\xbf#!")) {
        return {{"settings.script-shebang", severity::error,
            "Executable script content cannot be imported", std::string(path), 1, "executable-settings"}};
    }

    const auto png_prefix = starts({0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a});
    const auto jpeg_prefix = starts({0xff, 0xd8, 0xff});
    const auto dds_prefix = starts({'D', 'D', 'S', ' '});
    const auto riff_prefix = starts({'R', 'I', 'F', 'F'});
    const auto valid_png = png_prefix && contents.size() >= 24 && contents.substr(12, 4) == "IHDR";
    const auto valid_jpeg = jpeg_prefix && contents.size() >= 4 &&
        static_cast<unsigned char>(contents[contents.size() - 2]) == 0xff &&
        static_cast<unsigned char>(contents.back()) == 0xd9;
    const auto valid_dds = dds_prefix && contents.size() >= 128;
    const auto valid_wav = riff_prefix && contents.size() >= 12 && contents.substr(8, 4) == "WAVE";
    const auto recognized_media = valid_png || valid_jpeg || valid_dds || valid_wav;
    if (recognized_media) return {};
    if (png_prefix || jpeg_prefix || dds_prefix || riff_prefix) {
        return {{"settings.malformed-media", severity::error,
            "Recognized media header is truncated or malformed", std::string(path), 0, "binary-settings"}};
    }

    for (const auto byte : contents) {
        const auto value = static_cast<unsigned char>(byte);
        if (value < 0x20 && value != '\t' && value != '\n' && value != '\r' && value != '\f') {
            return {{"settings.unknown-binary", severity::error,
                "Unrecognized binary settings content cannot be imported", std::string(path), 0, "binary-settings"}};
        }
    }
    if (extension == ".lua") {
        bool malformed{};
        auto masked = mask_lua_literals(contents, malformed);
        if (malformed || !balanced_lua_delimiters(masked)) {
            return {{"settings.malformed-lua", severity::error,
                "Lua settings contain unterminated strings or unbalanced delimiters",
                std::string(path), 0, "dynamic-code"}};
        }
        mask_lua_table_keys(masked);
        auto findings = scan_lua(masked, path);
        const auto folded = ascii_casefold(masked);
        const std::regex require_expression("(^|[^a-z0-9_])require([^a-z0-9_]|$)");
        if (std::regex_search(folded, require_expression)) {
            findings.push_back({"settings.lua-require", severity::error,
                "Imported Lua settings cannot load modules", std::string(path), 0, "dynamic-code"});
        }
        return findings;
    }
    if (contents.find('\0') == std::string_view::npos) return {};
    return {{"settings.unknown-binary", severity::error,
        "Unrecognized binary settings content cannot be imported", std::string(path), 0, "binary-settings"}};
}

std::string json_escape(std::string_view value) {
    std::string output;
    output.reserve(value.size() + 8);
    for (const unsigned char c : value) {
        switch (c) {
            case '\"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (c < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    output += "\\u00";
                    output += hex[c >> 4]; output += hex[c & 0x0F];
                } else output += static_cast<char>(c);
        }
    }
    return output;
}

} // namespace vanahub
