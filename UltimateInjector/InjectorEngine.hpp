#ifndef INJECTOR_ENGINE_HPP
#define INJECTOR_ENGINE_HPP

#include "IWin32Wrapper.hpp"
#include <string>
#include <iostream>

class InjectorEngine {
private:
    IWin32Wrapper& win32Wrapper; // Reference to the Win32 wrapper function

    void CleanUp(HANDLE hProcess = NULL, LPVOID dllPathAddreess = NULL, HANDLE hThread = NULL);

    std::wstring GetAbsolutePath(const wchar_t* filePath);

    std::wstring GetFileNameFromPath(const wchar_t* filePath);

    DWORD GetProcessPidByName(const std::wstring& procName);

    HANDLE GetProcHandleByPid(DWORD pid);

    HMODULE GetModuleHandleByPid(DWORD pid, std::wstring moduleName);

    bool BasicDllInjection(DWORD targetPid, const wchar_t* dllPath);

    // More Techniques should be addedd in the future
public:
    InjectorEngine(IWin32Wrapper& win32Wrapper) : win32Wrapper(win32Wrapper) {}

    bool InjectDLL(DWORD targetPid, const wchar_t* dllPath, std::string technique = "basic");

    bool InjectDLL(const std::wstring& targetName, const wchar_t* dllPath, std::string technique = "basic");

    bool UninjectDLL(DWORD targetPid, const wchar_t* dllPath);

    bool UninjectDLL(const std::wstring& targetName, const wchar_t* dllPath);
};

#endif // INJECTOR_ENGINE_HPP