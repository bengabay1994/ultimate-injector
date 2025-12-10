#include "InjectorEngine.hpp"
#include <tlhelp32.h>
#include <filesystem>


bool InjectorEngine::InjectDLL(DWORD targetPid, const wchar_t* dllPath, std::string technique) {
    if (technique == "basic") {
        return BasicDllInjection(targetPid, dllPath);
    }
    return false;
}

bool InjectorEngine::InjectDLL(const std::wstring& targetName, const wchar_t* dllPath, std::string technique) {
    std::wstring absoDllPath = GetAbsolutePath(dllPath);
    if (absoDllPath.empty()) {
        std::wcerr << "[ERROR] Can't get the absolute path of the dll: " << dllPath << std::endl;
        return false;
    }
    if (!std::filesystem::exists(absoDllPath)) {
        std::wcerr << "[ERROR] Can't find dll file: " << absoDllPath << std::endl;
        return false;
    }
    DWORD targetPid = GetProcessPidByName(targetName);
    if (targetPid == 0) {
        return false;
    }
    return InjectDLL(targetPid, absoDllPath.c_str(), technique);
}

bool InjectorEngine::BasicDllInjection(DWORD targetPid, const wchar_t* dllPath) {
    // Getting the absolute path of the dll file
    std::wstring absoDllPath = GetAbsolutePath(dllPath);
    if (absoDllPath.empty()) {
        std::wcerr << "[ERROR] Can't get the absolute path of the dll: " << dllPath << std::endl;
        return false;
    }
    // Validate the dll exist
    if (!std::filesystem::exists(absoDllPath)) {
        std::wcerr << "[ERROR] Can't find dll file: " << absoDllPath << std::endl;
        return false;
    }
    // Dll was found
    std::wcout << "[INFO] Dll file was found successfuly!" << std::endl;

    // Step 1: Get a Handle to the process using pid or name
    HANDLE hProcess = GetProcHandleByPid(targetPid);
    if (hProcess == NULL) {
        return false;
    }
    // We have a valid Handle to the process we need to inject the dll into.
    std::wcout << "[INFO] Successfuly gained a handle to the target process!" << std::endl;


    // Step 2: Allocate memory inside the target process
    LPVOID dllPathInTargetProcess = win32Wrapper.VirtualAllocEx(hProcess, NULL, (absoDllPath.length() + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (dllPathInTargetProcess == NULL) {
        std::wcerr << "[ERROR] Failed to commit memory inside the target process for the dll path using VirtualAllocEx. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess);
        return false;
    }
    std::wcout << "[INFO] Commited memory inside target process for DLL Path string at: 0x" << std::hex << dllPathInTargetProcess << std::endl;

    // Step 3: Write the DLL path into the memory address we commited in step 2.
    SIZE_T numOfBytesWritten = 0;
    BOOL writeSucceeded = win32Wrapper.WriteProcessMemory(hProcess, dllPathInTargetProcess, absoDllPath.c_str(), (absoDllPath.length() + 1) * sizeof(wchar_t), &numOfBytesWritten);
    if (!writeSucceeded || (numOfBytesWritten < absoDllPath.length() + 1)) {
        std::wcerr << "[ERROR] Failed to write DLL path to memory in target process. NumberOfBytesWritten: " << numOfBytesWritten << ". Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, dllPathInTargetProcess);
        return false;
    }
    std::wcout << "[INFO] Wrote dll path to target process at address: 0x" << dllPathInTargetProcess << std::endl;


    // Step 4: Get the address of LoadLibraryW
    HMODULE hKernel32 = win32Wrapper.GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        std::wcerr << "[ERROR] Failed to get a handle to kernel32.dll. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, dllPathInTargetProcess);
        return false;
    }
    FARPROC loadLibraryAddress = win32Wrapper.GetProcAddress(hKernel32, "LoadLibraryW");
    if (loadLibraryAddress == NULL) {
        std::wcerr << "[ERROR] Failed to get the address of LoadLibraryW. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, dllPathInTargetProcess);
        return false;
    }

    // Step 5: Create a remote thread to execute LoadLibrary
    HANDLE hThread = win32Wrapper.CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathInTargetProcess, 0, NULL);
    if (hThread == NULL) {
        std::wcerr << "[ERROR] Failed to create a remote thread on target process. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, dllPathInTargetProcess);
        return false;
    }

    // Step 6: Wait for thread to finish executing and validate results
    DWORD waitResult = win32Wrapper.WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    if (win32Wrapper.GetExitCodeThread(hThread, &exitCode)) {
        if (exitCode == 0) {
            std::wcerr << "[ERROR] Remote thread encountered an error when executing LoadLibraryW!" << std::endl;
            CleanUp(hProcess, dllPathInTargetProcess, hThread);
            return false;
        }
    }
    else {
        std::wcerr << "[ERROR] Failed to get exit code of remote thread. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, dllPathInTargetProcess, hThread);
        return false;
    }
    std::wcout << "[INFO] Dll Injected Successfully!" << std::endl;
    std::wcout << "[INFO] Running CleanUp" << std::endl;
    CleanUp(hProcess, dllPathInTargetProcess, hThread);
    return true;
}

bool InjectorEngine::UninjectDLL(DWORD targetPid, const wchar_t* dllPath) {
    // Since this is uninjection we just need to get the name of the dll, we don't really care about the path.
    if (wcslen(dllPath) == 0) {
        std::wcerr << "[ERROR] DLL path is empty!" << std::endl;
        return false;
    }
    std::wstring dllName = GetFileNameFromPath(dllPath);
    if (dllName.empty()) {
        return false;
    }

    // Step 1: Get a handle to the target process
    HANDLE hProcess = GetProcHandleByPid(targetPid);
    if (hProcess == NULL) {
        return false;
    }
    std::wcout << "[INFO] Successfuly got a handle to the target process!" << std::endl;

    // Step 2: Get a handle to the module we want to uninject
    HMODULE moduleHandle = GetModuleHandleByPid(targetPid, dllName);
    if (moduleHandle == NULL) {
        CleanUp(hProcess);
        return false;
    }
    std::wcout << "[INFO] Successfuly got a handle to the module: " << dllName << ". Module Handle: " << moduleHandle << std::endl;
    
    // Step 3: Get the address of FreeLibrary
    HMODULE hKernel32 = win32Wrapper.GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        std::wcerr << "[ERROR] Failed to get a handle to kernel32.dll. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess);
        return false;
    }
    FARPROC freeLibraryAddress = win32Wrapper.GetProcAddress(hKernel32, "FreeLibrary");
    if (freeLibraryAddress == NULL) {
        std::wcerr << "[ERROR] Failed to get the address of FreeLibrary. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess);
        return false;
    }
    std::wcout << "[INFO] Got the address of FreeLibrary: 0x" << std::hex << std::uppercase << freeLibraryAddress << std::endl;

    // Step 4: Call CreateRemoteThread with the address of FreeLibrary
    HANDLE hThread = win32Wrapper.CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)freeLibraryAddress, moduleHandle, 0, NULL);
    if (hThread == NULL) {
        std::wcerr << "[ERROR] Failed to create a remote thread on target process. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess);
        return false;
    }
    
    // Step 5: Wait for thread to finish executing and validate results
    DWORD waitResult = win32Wrapper.WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    if (win32Wrapper.GetExitCodeThread(hThread, &exitCode)) {
        if (exitCode == 0) {
            std::wcerr << "[ERROR] Remote thread encountered an error when executing FreeLibrary!" << std::endl;
            CleanUp(hProcess, NULL, hThread);
            return false;
        }
    }
    else {
        std::wcerr << "[ERROR] Failed to get exit code of remote thread. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CleanUp(hProcess, NULL, hThread);
        return false;
    }
    std::wcout << "[INFO] Dll UnInjected Successfully!" << std::endl;
    std::wcout << "[INFO] Running CleanUp" << std::endl;
    CleanUp(hProcess, NULL, hThread);
    return true;
    
}

bool InjectorEngine::UninjectDLL(const std::wstring& targetName, const wchar_t* dllPath) {
    // Since this is uninjection we just need to get the name of the dll, we don't really care about the path.
    if (wcslen(dllPath) == 0) {
        std::wcerr << "[ERROR] DLL path is empty!" << std::endl;
        return false;
    }
    std::wstring dllName = GetFileNameFromPath(dllPath);
    if (dllName.empty()) {
        return false;
    }

    DWORD targetPid = GetProcessPidByName(targetName);
    if (targetPid == 0) {
        return false;
    }
    return UninjectDLL(targetPid, dllName.c_str());
}

void InjectorEngine::CleanUp(HANDLE hProcess, LPVOID dllPathAddressOnTargetProcess, HANDLE hThread) {
    std::wcout << "[INFO] Initiating clean up" << std::endl;
    if (hProcess != NULL) {
        if (dllPathAddressOnTargetProcess != NULL) {
            std::wcout << "[INFO] Freeing memory allocated on target process for dll path" << std::endl;
            win32Wrapper.VirtualFreeEx(hProcess, dllPathAddressOnTargetProcess, 0, MEM_RELEASE);
        }
        if (hThread != NULL) {
            std::wcout << "[INFO] Closing remote thread handle" << std::endl;
            win32Wrapper.CloseHandle(hThread);
        }
        std::wcout << "[INFO] Closing target process handle" << std::endl;
        win32Wrapper.CloseHandle(hProcess);
    }
}

DWORD InjectorEngine::GetProcessPidByName(const std::wstring& procName) {
    DWORD procPid = 0;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::wcout << "[INFO] Taking snapshot of all processes on the system" << std::endl;
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << "[ERROR] CreateToolhelp32Snapshot failed. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        return NULL;
    }

    std::wcout << "[INFO] Searching for process with \"" << procName << "\" in the name" << std::endl;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::wcerr << "[ERROR] Failed to retrieve information about the first process encountered in the system. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
    }
    HANDLE hProcess = NULL;
    do {
        std::wstring currentProcName(pe32.szExeFile); if (currentProcName.find(procName) != std::wstring::npos) {
            std::wcout << "[INFO] Found a process whose executable name contains proc_name. process: " << currentProcName << ". PID: " << pe32.th32ProcessID << std::endl;
            procPid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    if (procPid == 0) {
        std::wcerr << "[ERROR] Failed to find a process whose name contains: " << procName << std::endl;
    }
    return procPid;
}

HANDLE InjectorEngine::GetProcHandleByPid(DWORD pid) {
    HANDLE hProcess = win32Wrapper.OpenProcess(PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE,
        FALSE,
        pid
    );

    if (hProcess != NULL) {
        std::wcout << "[INFO] Successfully obtained a handle to process with PID: " << pid << std::endl;
        return hProcess;
    }
    std::wcerr << "[ERROR] Failed to obtain a handle to process with PID: " << pid << ". Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
    return NULL;
}

std::wstring InjectorEngine::GetAbsolutePath(const wchar_t* filePath) {
    try {
        std::filesystem::path absolutePath = std::filesystem::absolute(filePath);
        return absolutePath.wstring();
    }
    catch (const std::filesystem::filesystem_error& e) {
        // Handle potential errors
        std::wcerr << "[ERROR] Failed getting absolute path of the dll file. Error: " << e.what() << std::endl;
        return std::wstring();
    }
}

std::wstring InjectorEngine::GetFileNameFromPath(const wchar_t* filePath) {
    try {
        std::filesystem::path p(filePath);
        return p.filename().wstring();
    }
    catch (const std::filesystem::filesystem_error& e) {
        // Handle potential errors
        std::wcerr << "[ERROR] Failed getting file name of the dll file. Error: " << e.what() << std::endl;
        return std::wstring();
    }
}

HMODULE InjectorEngine::GetModuleHandleByPid(DWORD pid, std::wstring moduleName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << "[ERROR] CreateToolhelp32Snapshot for modules failed. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        return NULL;
    }

    std::wcout << "[INFO] Searching for the module \"" << moduleName << "\" in the process with pid: " << pid << std::endl;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hProcessSnap, &me32)) {
        std::wcerr << "[ERROR] Module32First failed. Error Code: 0x" << std::hex << std::uppercase << win32Wrapper.GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return NULL;
    }
    do {
        if (wcscmp(me32.szModule, moduleName.c_str()) == 0) {
            std::wcout << "[INFO] Found module \"" << moduleName << "\" in the process with pid: " << pid << std::endl;
            CloseHandle(hProcessSnap);
            return me32.hModule;
        }
    }while (Module32Next(hProcessSnap, &me32));

    std::wcerr << "[ERROR] Module \"" << moduleName << "\" not found in the process with pid: " << pid << std::endl;
    CloseHandle(hProcessSnap);
    return NULL;
}