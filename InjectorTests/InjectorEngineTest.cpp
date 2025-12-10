#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "InjectorEngine.hpp"
#include "MockWin32Wrapper.hpp"

#include <filesystem>

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;

class InjectorEngineTest : public ::testing::Test {
protected:
    NiceMock<MockWin32Wrapper> mockWin32Wrapper;
    InjectorEngine injectorEngine;
    DWORD targetPid = 1234;
    const wchar_t* dllPath = L"..\\..\\x64\\Release\\TestDll.dll";

    InjectorEngineTest() : injectorEngine(mockWin32Wrapper) {}

    void SetUp() override {
        // Default expectations for a successful path (can be overridden in specific tests)
        // Note: Tests should set specific expectations.
    }
};

TEST_F(InjectorEngineTest, InjectDLL_Success) {
    HANDLE hProcess = (HANDLE)0x1;
    LPVOID allocatedMem = (LPVOID)0x1000;
    HMODULE hKernel32 = (HMODULE)0x2000;
    FARPROC loadLibraryAddr = (FARPROC)0x3000;
    HANDLE hThread = (HANDLE)0x2;

    EXPECT_CALL(mockWin32Wrapper, OpenProcess(_, _, targetPid))
        .WillOnce(Return(hProcess));

    EXPECT_CALL(mockWin32Wrapper, VirtualAllocEx(hProcess, _, _, _, _))
        .WillOnce(Return(allocatedMem));

    EXPECT_CALL(mockWin32Wrapper, WriteProcessMemory(hProcess, allocatedMem, _, _, _))
        .WillOnce(DoAll(SetArgPointee<4>(std::filesystem::absolute(dllPath).wstring().length() + 1), Return(TRUE)));

    EXPECT_CALL(mockWin32Wrapper, GetModuleHandleW(_))
        .WillOnce(Return(hKernel32));

    EXPECT_CALL(mockWin32Wrapper, GetProcAddress(hKernel32, _))
        .WillOnce(Return(loadLibraryAddr));

    EXPECT_CALL(mockWin32Wrapper, CreateRemoteThread(hProcess, _, _, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMem, _, _))
        .WillOnce(Return(hThread));

    EXPECT_CALL(mockWin32Wrapper, WaitForSingleObject(hThread, _))
        .WillOnce(Return(WAIT_OBJECT_0));

    EXPECT_CALL(mockWin32Wrapper, GetExitCodeThread(hThread, _))
        .WillOnce(DoAll(SetArgPointee<1>(1), Return(TRUE))); // Exit code 1 means success usually, or at least not 0

    // Cleanup expectations
    EXPECT_CALL(mockWin32Wrapper, VirtualFreeEx(hProcess, allocatedMem, _, _)).Times(1);
    EXPECT_CALL(mockWin32Wrapper, CloseHandle(hThread)).Times(1);
    EXPECT_CALL(mockWin32Wrapper, CloseHandle(hProcess)).Times(1);

    EXPECT_TRUE(injectorEngine.InjectDLL(targetPid, dllPath));
}

TEST_F(InjectorEngineTest, OpenProcess_Fails) {
    EXPECT_CALL(mockWin32Wrapper, OpenProcess(_, _, targetPid))
        .WillOnce(Return(nullptr));

    EXPECT_FALSE(injectorEngine.InjectDLL(targetPid, dllPath));
}

TEST_F(InjectorEngineTest, VirtualAllocEx_Fails) {
    HANDLE hProcess = (HANDLE)0x1;

    EXPECT_CALL(mockWin32Wrapper, OpenProcess(_, _, targetPid))
        .WillOnce(Return(hProcess));

    EXPECT_CALL(mockWin32Wrapper, VirtualAllocEx(hProcess, _, _, _, _))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(mockWin32Wrapper, CloseHandle(hProcess)).Times(1);

    EXPECT_FALSE(injectorEngine.InjectDLL(targetPid, dllPath));
}

TEST_F(InjectorEngineTest, CreateRemoteThread_Fails) {
    HANDLE hProcess = (HANDLE)0x1;
    LPVOID allocatedMem = (LPVOID)0x1000;
    HMODULE hKernel32 = (HMODULE)0x2000;
    FARPROC loadLibraryAddr = (FARPROC)0x3000;

    EXPECT_CALL(mockWin32Wrapper, OpenProcess(_, _, targetPid))
        .WillOnce(Return(hProcess));

    EXPECT_CALL(mockWin32Wrapper, VirtualAllocEx(hProcess, _, _, _, _))
        .WillOnce(Return(allocatedMem));

    EXPECT_CALL(mockWin32Wrapper, WriteProcessMemory(hProcess, allocatedMem, _, _, _))
        .WillOnce(DoAll(SetArgPointee<4>(std::filesystem::absolute(dllPath).wstring().length() + 1), Return(TRUE)));

    EXPECT_CALL(mockWin32Wrapper, GetModuleHandleW(_))
        .WillOnce(Return(hKernel32));

    EXPECT_CALL(mockWin32Wrapper, GetProcAddress(hKernel32, _))
        .WillOnce(Return(loadLibraryAddr));

    EXPECT_CALL(mockWin32Wrapper, CreateRemoteThread(hProcess, _, _, _, _, _, _))
        .WillOnce(Return(nullptr));

    // Cleanup expectations
    EXPECT_CALL(mockWin32Wrapper, VirtualFreeEx(hProcess, allocatedMem, _, _)).Times(1);
    // No hThread to close
    EXPECT_CALL(mockWin32Wrapper, CloseHandle(hProcess)).Times(1);

    EXPECT_FALSE(injectorEngine.InjectDLL(targetPid, dllPath));
}
