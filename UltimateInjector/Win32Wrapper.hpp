#ifndef WIN32WRAPPER_HPP
#define WIN32WRAPPER_HPP

#include "IWin32Wrapper.hpp"

class Win32Wrapper : public IWin32Wrapper {
public:
    Win32Wrapper() {}
    ~Win32Wrapper() {}

    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) override;

    LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) override;

    BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) override;

    BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) override;

    HMODULE GetModuleHandleW(LPCWSTR lpModuleName) override;

    FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) override;

    HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) override;

    DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMiliseconds) override;

    BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) override;

    BOOL CloseHandle(HANDLE hObject) override;

    DWORD GetLastError() override;
};
#endif // WIN32WRAPPER_HPP