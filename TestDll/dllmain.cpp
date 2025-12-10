// injected_simple.cpp
#include <windows.h>
#include <fstream>
#include <string>

DWORD WINAPI WriteInfoThread(LPVOID) {
    // Get PID
    DWORD pid = GetCurrentProcessId();

    // Get image path
    wchar_t imagePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, imagePath, MAX_PATH)) {
        wcscpy_s(imagePath, L"<unknown process name>");
    }

    // Get %TEMP% path
    wchar_t tempDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir)) {
        wcscpy_s(tempDir, L".\\");
    }

    // Build full path
    std::wstring outPath = std::wstring(tempDir) + L"Injection.txt";
    char imageUtf8[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, imagePath, -1, imageUtf8, MAX_PATH, NULL, NULL);

    // Open file with fstream
    std::ofstream outfile(outPath);

    outfile << "PID=" << pid << std::endl;
    outfile << "Image=" << imageUtf8 << std::endl;
    outfile.close();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, WriteInfoThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
