#include "gmock/gmock.h"

#ifndef MOCKWIN32WRAPPER_HPP
#define MOCKWIN32WRAPPER_HPP

#include "IWin32Wrapper.hpp"

class MockWin32Wrapper : public IWin32Wrapper {
public:
    MOCK_METHOD(HANDLE, OpenProcess, (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId), (override));
    MOCK_METHOD(LPVOID, VirtualAllocEx, (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect), (override));
    MOCK_METHOD(BOOL, WriteProcessMemory, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten), (override));
    MOCK_METHOD(BOOL, VirtualFreeEx, (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType), (override));
    MOCK_METHOD(HMODULE, GetModuleHandleW, (LPCWSTR lpModuleName), (override));
    MOCK_METHOD(FARPROC, GetProcAddress, (HMODULE hModule, LPCSTR lpProcName), (override));
    MOCK_METHOD(HANDLE, CreateRemoteThread, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId), (override));
    MOCK_METHOD(DWORD, WaitForSingleObject, (HANDLE hHandle, DWORD dwMiliseconds), (override));
    MOCK_METHOD(BOOL, GetExitCodeThread, (HANDLE hThread, LPDWORD lpExitCode), (override));
    MOCK_METHOD(BOOL, CloseHandle, (HANDLE hObject), (override));
    MOCK_METHOD(DWORD, GetLastError, (), (override));
};

#endif // MOCKWIN32WRAPPER_HPP