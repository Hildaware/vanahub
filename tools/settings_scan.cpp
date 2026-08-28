#include "vanahub/core.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: vanahub_settings_scan <display-path> <file>\n";
        return 2;
    }
    std::ifstream input(argv[2], std::ios::binary);
    if (!input) {
        std::cerr << "could not read settings file\n";
        return 2;
    }
    const std::string contents((std::istreambuf_iterator<char>(input)), {});
    const auto findings = vanahub::scan_setting(contents, argv[1]);
    if (findings.empty()) return 0;
    for (const auto& finding : findings) {
        std::cout << finding.rule_id << '\t' << finding.path << '\t'
                  << finding.line << '\t' << finding.message << '\n';
    }
    return 1;
}
