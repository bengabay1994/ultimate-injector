#include "ArgumentParser.hpp"
#include <iostream>
#include <vector>
#include <algorithm>

ParsedArguments ArgumentParser::Parse(int argc, wchar_t* argv[], std::string version) {
    ParsedArguments args;
    args.sVersion = version;

    bool targetProcessSet = false;
    bool targetPidSet = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        if (arg == L"-h" || arg == L"--help") {
            args.help = true;
            return args; // Return early if help is requested
        }
        else if (arg == L"--version") {
            args.version = true;
            return args; // Return early if version is requested
        }
        else if (arg == L"-u" || arg == L"--uninject") {
            args.uninject = true;
        }
        else if (arg == L"-P" || arg == L"--process") {
            if (i + 1 < argc) {
                if (targetPidSet) {
                    std::wcerr << L"[ERROR] Cannot use both -P/--process and -p/--pid at the same time." << std::endl;
                    args.help = true;
                    return args; 
                }
                args.processName = argv[++i];
                targetProcessSet = true;
            }
            else {
                std::wcerr << L"[ERROR] Missing value for --process" << std::endl;
                args.help = true;
                return args; 
            }
        }
        else if (arg == L"-p" || arg == L"--pid") {
            if (i + 1 < argc) {
                if (targetProcessSet) {
                    std::wcerr << L"[ERROR] Cannot use both -P/--process and -p/--pid at the same time." << std::endl;
                    args.help = true;
                    return args; 
                }
                std::wstring pidStr = argv[++i];
                wchar_t* endptr;
                if (pidStr.length() >= 2 && pidStr[0] == L'0' && (pidStr[1] == L'x' || pidStr[1] == L'X')) {
                    args.pid = wcstoul(pidStr.c_str(), &endptr, 16);
                }
                else {
                    args.pid = wcstoul(pidStr.c_str(), &endptr, 10);
                }

                if (*endptr != L'\0') {
                    std::wcerr << L"[ERROR] Invalid PID format: " << pidStr << std::endl;
                    args.help = true;
                    return args; 
                }
                targetPidSet = true;
            }
            else {
                std::wcerr << L"[ERROR] Missing value for --pid" << std::endl;
                args.help = true;
                return args; 
            }
        }
        else if (arg == L"-d" || arg == L"--dll") {
            if (i + 1 < argc) {
                args.dllPath = argv[++i];
            }
            else {
                std::wcerr << L"[ERROR] Missing value for --dll" << std::endl;
                args.help = true;
                return args; 
            }
        }
        else if (arg == L"-t" || arg == L"--technique") {
            if (i + 1 < argc) {
                std::wstring techW = argv[++i];
                // convert to lower case for easier comparison
                std::transform(techW.begin(), techW.end(), techW.begin(), [](wchar_t c) {return std::tolower(c, std::locale()); });

                if (techW == L"b" || techW == L"basic") {
                    args.technique = "basic";
                }
                else {
                    std::wcerr << L"[ERROR] Unsupported technique: " << techW << std::endl;
                    args.help = true;
                    return args;
                }
                
            }
            else {
                std::wcerr << L"[ERROR] Missing value for --technique" << std::endl;
                args.help = true;
                return args; 
            }
        }
        else {
            std::wcerr << L"[WARNING] Unknown argument: " << arg << std::endl;
            args.help = true;
            return args; 
        }
    }

    // Validation
    if (args.dllPath.empty()) {
        std::wcerr << L"[ERROR] DLL path is required (-d/--dll)." << std::endl;
        args.help = true;
        return args; 
    }
    
    if (targetProcessSet && targetPidSet) {
        std::wcerr << L"[ERROR] Only one target can be specified (-p or -P) but never both." << std::endl;
        args.help = true;
        return args; 
    }
    
    if (!targetProcessSet && !targetPidSet) {
         // Error will be shown in main if we don't do it here. 
         // User asked to make code in ArgumentParser follow rules.
         // So I will print error here too if not help/version.
         if (!args.help && !args.version) {
             std::wcerr << L"[ERROR] At least 1 target specifier is required (-p or -P)." << std::endl;
             args.help = true;
             return args; 
         }
    }
    
    return args;
}

void ArgumentParser::ShowHelp() {
    std::cout << "UltimateInjector - A DLL Injection Tool" << std::endl;
    std::cout << "Usage: .\UltInjector.exe (-p <pid> | -P <name>) -d <path> [-u] [-t <technique>] [--help] [--version]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help            Show this help message" << std::endl;
    std::cout << "  --version             Show version information" << std::endl;
    std::cout << "  -P, --process <name>  Process name or part of it (first match is targeted)" << std::endl;
    std::cout << "  -p, --pid <id>        Process PID (decimal or 0x hex)" << std::endl;
    std::cout << "  -d, --dll <path>      Path to the DLL to inject/uninject (REQUIRED)" << std::endl;
    std::cout << "  -u, --uninject        Uninject the DLL from the target process (Optional)" << std::endl;
    std::cout << "  -t, --technique <t>   Injection technique (Optional, default: basic)" << std::endl;
    std::cout << "                        Supported values: b - basic (more will be added in the future)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  Inject by PID (Decimal):" << std::endl;
    std::cout << "    .\UltInjector.exe -p 1234 -d \"C:\\MyDll.dll\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  Inject by PID (Hex):" << std::endl;
    std::cout << "    .\UltInjector.exe -p 0x1234 -d \"C:\\MyDll.dll\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  Inject by Process Name:" << std::endl;
    std::cout << "    .\UltInjector.exe -P notepad -d \"C:\\MyDll.dll\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  Uninject from Process:" << std::endl;
    std::cout << "    .\UltInjector.exe -u -P notepad -d \"C:\\MyDll.dll\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  Inject using Basic Technique:" << std::endl;
    std::cout << "    .\UltInjector.exe -P notepad -d \"C:\\MyDll.dll\" -t basic" << std::endl;
}