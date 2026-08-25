#include "vanahub/core.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <regex>
#include <set>

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
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)) return false;
    const auto extension = ascii_casefold(value.substr(dot));
    static const std::set<std::string> allowed{
        ".lua", ".json", ".ini", ".xml", ".txt", ".md", ".png", ".jpg", ".jpeg", ".dds", ".wav"
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
