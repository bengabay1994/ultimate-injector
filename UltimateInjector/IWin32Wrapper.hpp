#ifndef IWIN32WRAPPER_HPP
#define IWIN32WRAPPER_HPP

#include <windows.h>
#include <string>

class IWin32Wrapper {
public:
    virtual ~IWin32Wrapper() = default;

    virtual HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = 0;

    virtual LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) = 0;

    virtual BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = 0;

    virtual BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = 0;

    virtual HMODULE GetModuleHandleW(LPCWSTR lpModuleName) = 0;

    virtual FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) = 0;

    virtual HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = 0;

    virtual DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMiliseconds) = 0;

    virtual BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) = 0;

    virtual BOOL CloseHandle(HANDLE hObject) = 0;

    virtual DWORD GetLastError() = 0;
};
#endif // IWIN32WRAPPER_HPP