#include "winapiutils.h"

static
PVOID
GetPebAddress(HANDLE pHandle) {
    _NtQueryInformationProcess NtQueryInformationProcess =
        (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    return pbi.PebBaseAddress;
}

static
WCHAR *
GetProcessCommandLine(HANDLE pHandle, DWORD *exitTag, DWORD *lastErrorCode) {
    PVOID rtlurp;
    UNICODE_STRING cmdln;

    PVOID peba = GetPebAddress(pHandle);

    // Get the address of ProcessParameters.
    if (!ReadProcessMemory(pHandle, (PCHAR)peba + FIELD_OFFSET(PEB, ProcessParameters), &rtlurp, sizeof(rtlurp), NULL)) {
        // Could not read the address of ProcessParameters.
        *exitTag = 1;
        *lastErrorCode = GetLastError();
        return NULL;
    }

    // Read the CommandLine UNICODE_STRING structure.
    if (!ReadProcessMemory(pHandle, (PCHAR)rtlurp + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine), &cmdln, sizeof(cmdln), NULL)) {
        // Could not read the address of CommandLine.
        *exitTag = 2;
        *lastErrorCode = GetLastError();
        return NULL;
    }

    // Allocate memory to hold the command line.
    WCHAR *cmdlncnts = malloc(cmdln.Length);
    if (NULL == cmdlncnts) {
        *exitTag = 3;
        return NULL;
    }

    // Read the command line contents.
    if (!ReadProcessMemory(pHandle, cmdln.Buffer, cmdlncnts, cmdln.Length, NULL)) {
        // Could not read the command line string.
        *exitTag = 4;
        *lastErrorCode = GetLastError();
        free(cmdlncnts);
        cmdlncnts = NULL;
        return NULL;
    }

    WCHAR *result = malloc(cmdln.Length + 2);
    if(result == NULL) {
        *exitTag = 5;
        *lastErrorCode = GetLastError();
        free(cmdlncnts);
        cmdlncnts = NULL;
        return NULL;
    }
    memcpy(result, cmdlncnts, cmdln.Length);
    // ... plus two bytes (size of WCHAR) for a nul-terminator.
    *(WCHAR*)((char*)result + cmdln.Length) = 0x0000L;
    free(cmdlncnts);
    cmdlncnts = NULL;

    return result;
}

static
BOOL
IsRemote(DWORD pid, DWORD *exitTag, DWORD *lastErrorCode) {
    DWORD sessionId;
    if (FALSE == ProcessIdToSessionId(pid, &sessionId)) {
        *exitTag = 1;
        *lastErrorCode = GetLastError();
        return FALSE;
    }

    OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

    GetVersionExW(&osvi);
    if (osvi.dwMajorVersion > 5) {
        // The case of Vista/Server 2008: 0 and 1 means local, greater than 1 - remote.
        return (0 != sessionId) && (1 != sessionId);
    } else if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion >= 1)) {
        // The case of XP/Server 2003: 0 is local, another value means remote.
        return (0 != sessionId);
    } else {
        *exitTag = 2;
        return FALSE;
    }
}

UserProfile *
GetCurrentProcessUserProfile(DWORD *exitTag) {
    return GetProcessUserProfile(GetCurrentProcess(), exitTag);
}

UserProfile *
GetProcessUserProfile(HANDLE hProcess, DWORD *exitTag) {
    HANDLE hToken = NULL;
    DWORD dwDomainSize = 0;
    DWORD dwNameSize = 0;

    if (FALSE == OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        *exitTag = 1;
        goto exit;
    }

    TOKEN_ELEVATION elevation;
    DWORD teSize = sizeof(TOKEN_ELEVATION);
    BOOL res = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &teSize);
    if (0 == res) {
        *exitTag = 2;
        goto exit;
    }

    DWORD tuSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tuSize);
    TOKEN_USER *pTu = malloc(tuSize);
    if (NULL == pTu) {
        *exitTag = 3;
        goto exit;
    }

    res = GetTokenInformation(hToken, TokenUser, pTu, tuSize, &tuSize);
    if (0 == res) {
        *exitTag = 4;
        goto exit;
    }

    SID_NAME_USE snu;
    LookupAccountSidW(NULL, pTu->User.Sid, NULL, &dwNameSize, NULL, &dwDomainSize, &snu);

    WCHAR *name = malloc(dwNameSize * sizeof(WCHAR));
    if (NULL == name) {
        *exitTag = 5;
        goto exit;
    }
    WCHAR *domain = malloc(dwDomainSize * sizeof(WCHAR));
    if (NULL == name) {
        *exitTag = 6;
        goto exit;
    }
    res = LookupAccountSidW(NULL, pTu->User.Sid, name, &dwNameSize, domain, &dwDomainSize, &snu);
    if (0 == res) {
        *exitTag = 7;
        goto exit;
    }

    UserProfile *up = malloc(sizeof(*up));
    if (NULL == up) {
        *exitTag = 8;
        goto exit;
    }

    WCHAR *sidStr = NULL;
    res = ConvertSidToStringSidW(pTu->User.Sid, &sidStr);
    if (0 == res) {
        *exitTag = 9;
        goto exit;
    }

    up->Name = malloc(sizeof(WCHAR) * (wcslen(name) + 1));
    if (NULL == up->Name) {
        *exitTag = 10;
        goto exit;
    }
    wcscpy_s(up->Name, wcslen(name) + 1, name);

    up->Domain = malloc(sizeof(WCHAR) * (wcslen(domain) + 1));
    if (NULL == up->Domain) {
        *exitTag = 11;
        goto exit;
    }
    wcscpy_s(up->Domain, wcslen(domain) + 1, domain);

    up->SID = malloc(sizeof(WCHAR) * (wcslen(sidStr) + 1));
    if (NULL == up->SID) {
        *exitTag = 12;
        goto exit;
    }
    wcscpy_s(up->SID, wcslen(sidStr) + 1, sidStr);

    up->Elevated = elevation.TokenIsElevated;

exit:
    if (NULL != hToken) {
        CloseHandle(hToken);
    }
    if (NULL != pTu) {
        free(pTu); pTu = NULL;
    }
    if (NULL != name) {
        free(name); name = NULL;
    }
    if (NULL != domain) {
        free(domain); domain = NULL;
    }
    if (NULL != sidStr) {
        LocalFree(sidStr); sidStr = NULL;
    }
    if (0 != *exitTag) {
        if (NULL != up) {
            free(up); up = NULL;
        }
    }

    return up;
}

VOID
FreeUserProfile(UserProfile *up) {
    free(up->Name);
    free(up->Domain);
    free(up->SID);
    free(up);
}

WCHAR *
GetCurrentExecutableFullName(DWORD *exitTag, DWORD *lastErrorCode) {
    WCHAR *fileName = malloc(MAX_NAME_PATH * sizeof(*fileName));
    if (NULL == fileName) {
        *exitTag = 1;
        return NULL;
    }

    if (0 == GetModuleFileNameW(NULL, fileName, MAX_PATH)) {
        *exitTag = 2;
        *lastErrorCode = GetLastError();
        free(fileName);
        return NULL;
    }

    return fileName;
}

WCHAR *
GetProcessNameInDeviceForm(HANDLE hProcess, DWORD *exitTag, DWORD *lastErrorCode) {
    WCHAR *fileName = malloc(sizeof(*fileName) * MAX_NAME_PATH);
    if (NULL == fileName) {
        *exitTag = 1;
        return NULL;
    }

    if (0 == GetProcessImageFileNameW(hProcess, fileName, MAX_PATH)) {
        *exitTag = 2;
        *lastErrorCode = GetLastError();
        free(fileName);
        return NULL;
    }

    return fileName;
}

OSProcess *
GetOSProcesses(DWORD *n, DWORD *exitTag, DWORD *lastErrorCode) {
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
    OSProcess *procs = malloc(sizeof(*procs) * 2048);
    if (NULL == procs) {
        *exitTag = 2;
        return NULL;
    }

    // Walkthrough a snapshot of all OS processes.
    if (Process32FirstW(snapshot, &process)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.th32ProcessID);
            if (NULL == hProcess) {
                // Ignore the process.
                continue;
            }

            procs[i].PID = process.th32ProcessID;
            procs[i].PPID = process.th32ParentProcessID;
            procs[i].IsRemote = IsRemote(process.th32ProcessID, exitTag, lastErrorCode);
            if (0 != *exitTag) {
                CloseHandle(hProcess);
                *exitTag = 0;
                continue;
            }
            procs[i].ExecName = GetProcessNameInDeviceForm(hProcess, exitTag, lastErrorCode);
            if (0 != *exitTag) {
                CloseHandle(hProcess);
                *exitTag = 0;
                continue;
            }
            procs[i].CommandLine = GetProcessCommandLine(hProcess, exitTag, lastErrorCode);
            if (0 != *exitTag) {
                free(procs[i].ExecName);
                CloseHandle(hProcess);
                *exitTag = 0;
                continue;
            }
            procs[i].UProfile = GetProcessUserProfile(hProcess, exitTag);
            if (0 != *exitTag) {
                free(procs[i].ExecName);
                free(procs[i].CommandLine);
                FreeUserProfile(procs[i].UProfile);
                CloseHandle(hProcess);
                *exitTag = 0;
                continue;
            }

            CloseHandle(hProcess);
            // Increment index only if OSProccesEx has been filled correctly.
            ++i;
        } while (Process32NextW(snapshot, &process));
    } else {
        // Could not retrieve information about the first process.
        *exitTag = 3;
        free(procs);
        procs = NULL;
    }
    CloseHandle(snapshot);
    *n = i;
    return procs;
}

VOID
FreeOSProcesses(OSProcess *osprocs, DWORD n) {
    DWORD i;
    for (i = 0; i < n; i++) {
        free(osprocs[i].ExecName);
        free(osprocs[i].CommandLine);
        FreeUserProfile(osprocs[i].UProfile);
    }
    free(osprocs);
}
