#include "Win32Wrapper.hpp"

HANDLE Win32Wrapper::OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    return ::OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

LPVOID Win32Wrapper::VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
    return ::VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL Win32Wrapper::WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    return ::WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL Win32Wrapper::VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    return ::VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
}

HMODULE Win32Wrapper::GetModuleHandleW(LPCWSTR lpModuleName) {
    return ::GetModuleHandleW(lpModuleName);
}

FARPROC Win32Wrapper::GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    return ::GetProcAddress(hModule, lpProcName);
}

HANDLE Win32Wrapper::CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    return ::CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

DWORD Win32Wrapper::WaitForSingleObject(HANDLE hHandle, DWORD dwMiliseconds) {
    return ::WaitForSingleObject(hHandle, dwMiliseconds);
}

BOOL Win32Wrapper::GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
    return ::GetExitCodeThread(hThread, lpExitCode);
}

BOOL Win32Wrapper::CloseHandle(HANDLE hObject) {
    return ::CloseHandle(hObject);
}

DWORD Win32Wrapper::GetLastError() {
    return ::GetLastError();
}