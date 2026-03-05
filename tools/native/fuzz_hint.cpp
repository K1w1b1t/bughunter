#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string target = argc > 1 ? argv[1] : "";
    int hint = 5;
    if (target.find("api") != std::string::npos) hint += 15;
    if (target.find("internal") != std::string::npos) hint += 25;
    std::cout << "{\"module\":\"cpp_fuzz_hint\",\"target\":\"" << target << "\",\"hint\":" << hint << "}" << std::endl;
    return 0;
}
