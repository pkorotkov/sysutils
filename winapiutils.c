#include "winapiutils.h"

BOOL
IsElevated(void) {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD teSize = sizeof(TOKEN_ELEVATION);
        if(GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &teSize)) {
            fRet = elevation.TokenIsElevated;
        }
    }

    if(hToken) {
        CloseHandle(hToken);
    }

    return fRet;
}

// exitTag is the last error code.
WCHAR *
GetExecutableFullName(DWORD *exitTag) {
    WCHAR *fileName = malloc(MAX_NAME_PATH * sizeof(*fileName));
    // Set NULL for self name.
    HMODULE module = NULL; // module = GetModuleHandle(L"some-module");
    DWORD size = GetModuleFileNameW(module, fileName, MAX_PATH);

    *exitTag = GetLastError();

    return fileName;
}

PROCESSENTRY32W *
GetOSProcesses(DWORD *n, DWORD *exitTag) {
    // Create toolhelp snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(INVALID_HANDLE_VALUE == snapshot) {
        *exitTag = 1;
        return NULL;
    }

    PROCESSENTRY32W process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);
    
    DWORD i = 0;
    PROCESSENTRY32W *procs = malloc(sizeof(PROCESSENTRY32W) * 2048);

    // Walkthrough all processes.
    if (Process32FirstW(snapshot, &process)) {
        do {
            procs[i] = process;
            ++i;
        } while (Process32NextW(snapshot, &process));
    } else {
        // Could not retrieve information about the first process.
        *exitTag = 2;
        free(procs);
        procs = NULL;
    }
    CloseHandle(snapshot);
    *n = i;
    return procs;
}