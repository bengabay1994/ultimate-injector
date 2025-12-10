#ifndef ARGUMENTPARSER_HPP
#define ARGUMENTPARSER_HPP

#include <string>
#include <windows.h>

struct ParsedArguments {
    bool help = false;
    bool version = false;
    bool uninject = false;
    std::wstring processName;
    DWORD pid = 0;
    std::wstring dllPath;
    std::string technique = "basic";
    std::string sVersion = "1.0.0";
    // Helper to check if a valid target is set
    bool HasTarget() const {
        return pid != 0 || !processName.empty();
    }
};

class ArgumentParser {
private:
public:
    static ParsedArguments Parse(int argc, wchar_t* argv[], std::string version = "1.0.0");
    static void ShowHelp();
};

#endif // ARGUMENTPARSER_HPP
