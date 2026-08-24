#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace vanahub {

enum class severity { warning, error };

struct finding {
    std::string rule_id;
    severity level{severity::error};
    std::string message;
    std::string path;
    std::uint32_t line{};
    std::string capability;
};

struct archive_limits {
    std::uint64_t compressed_bytes{50ull * 1024 * 1024};
    std::uint64_t expanded_bytes{200ull * 1024 * 1024};
    std::uint64_t entry_bytes{50ull * 1024 * 1024};
    std::uint32_t entries{4096};
    std::uint32_t compression_ratio{200};
};

bool is_safe_relative_path(std::string_view value, std::string* reason = nullptr);
bool is_safe_package_id(std::string_view value);
bool is_allowed_extension(std::string_view value);
std::string ascii_casefold(std::string_view value);
std::vector<finding> scan_lua(std::string_view source, std::string_view path);
std::string json_escape(std::string_view value);

} // namespace vanahub
