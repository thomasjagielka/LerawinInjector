#include <windows.h>
#include <TlHelp32.h>
#include <string>

int FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 1;
}

HANDLE InjectDll(const char* filePath, int pid)
{
    // Retrieve a handle to the target process.
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Get the full path of the dll file.
    char fullDLLPath[_MAX_PATH];
    GetFullPathNameA(filePath, _MAX_PATH, fullDLLPath, NULL);

    // Allocate memory in the target process.
    LPVOID DLLPath_addr = VirtualAllocEx(h_process, NULL, _MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (DLLPath_addr) {
        // Restore original NtOpenFile from external process.
        LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
        char patchedBytes[5];

        if (ntOpenFile) {
            // Backup patched bytes.
            ReadProcessMemory(h_process, ntOpenFile, patchedBytes, 5, NULL);

            char originalBytes[5];
            memcpy(originalBytes, ntOpenFile, 5);
            WriteProcessMemory(h_process, ntOpenFile, originalBytes, 5, NULL);
        }

        // Write the dll path into that memory.
        WriteProcessMemory(h_process, DLLPath_addr, fullDLLPath, strlen(fullDLLPath), NULL);                                    

        // Get LoadLibraryA address (same across all processes) to start execution at it.
        LPVOID LoadLib_addr = GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA");

        // Start a remote execution thread at LoadLibraryA and pass the dll path as an argument.
        HANDLE h_rThread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLib_addr, DLLPath_addr, 0, NULL);

        // Wait for it to be finished.
        WaitForSingleObject(h_rThread, INFINITE);

        DWORD exit_code;
        // Retrieve the return value, i.e., the module.
        GetExitCodeThread(h_rThread, &exit_code);                                         

        // Free the injected thread handle.
        CloseHandle(h_rThread);                 
        // And the memory allocated for the DLL path.
        VirtualFreeEx(h_process, 0, 0, MEM_RELEASE);               
        // And the handle for the target process.
        CloseHandle(h_process);

        // Restore patched bytes.
        WriteProcessMemory(h_process, ntOpenFile, patchedBytes, 5, NULL);

        return (HANDLE)exit_code;
    }

    return (HANDLE)1;
}

int main(char* argv[]) {
    InjectDll("LerawinInternal.dll", FindProcessId(L"csgo.exe"));
}