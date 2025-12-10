#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <stdlib.h>
#include "ArgumentParser.hpp"
#include "InjectorEngine.hpp"
#include "IWin32Wrapper.hpp"
#include "Win32Wrapper.hpp"

// #include "argparse.hpp" // maybe migrate to it in the future. it doesn't support wchar_t arguments at all for now.

#define MAX_PATH 260

int wmain(int argc, wchar_t* argv[]) // NOLINT
{
    try {
        ParsedArguments args = ArgumentParser::Parse(argc, argv, "1.0.0");

        if (args.help) {
            ArgumentParser::ShowHelp();
            return 0;
        }

        if (args.version) {
            std::cout << args.sVersion << std::endl;
            return 0;
        }

        if (args.dllPath.empty()) {
            std::wcerr << L"[ERROR] DLL path is required. Use -d or --dll." << std::endl;
            ArgumentParser::ShowHelp();
            return -1;
        }

        if (!args.HasTarget()) {
            std::wcerr << L"[ERROR] You must specify a target process via --process or --pid." << std::endl;
            ArgumentParser::ShowHelp();
            return -1;
        }

        Win32Wrapper win32Wrapper;
        InjectorEngine injectorEngine(win32Wrapper);
        bool success = false;
        std::wstring action = args.uninject ? L"Uninject" : L"Inject";
        if (args.pid != 0) {
            if (args.uninject) {
                success = injectorEngine.UninjectDLL(args.pid, args.dllPath.c_str());
            }
            else {
                std::cout << "[INFO] Injection technique: " << args.technique << std::endl;
                success = injectorEngine.InjectDLL(args.pid, args.dllPath.c_str());
            }
        }
        else {
            if (args.uninject) {
                success = injectorEngine.UninjectDLL(args.processName, args.dllPath.c_str());
            }
            else {
                success = injectorEngine.InjectDLL(args.processName, args.dllPath.c_str());
            }
        }
        if (!success) {
            std::wcerr << L"[ERROR] Failed to " << action <<" the DLL" << std::endl;
            return -1;
        }
        std::wcout << L"[INFO] DLL " << action << "ed successfully!" << std::endl;

    }
    catch (std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return -1;
    }
    catch (...) {
        std::cerr << "Exception of unknown type!" << std::endl;
        return -1;
    }

    return 0;
}