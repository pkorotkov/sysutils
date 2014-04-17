#include "winapiutils.h"

VOID
FreeUserProfile(UserProfile *up) {
    free(up->Name);
    free(up->Domain);
    free(up->SID);
    free(up);
}

UserProfile *
GetCurrentProcessUserProfile(DWORD *exitTag) {
    HANDLE hToken = NULL;
    TOKEN_USER *pTu = NULL;
    DWORD dwDomainSize = 0;
    DWORD dwNameSize = 0;
    WCHAR *name;
    WCHAR *domain;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            *exitTag = 1;
            goto exit;
        }
        
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            *exitTag = 2;
            goto exit;
        }
    }

    TOKEN_ELEVATION elevation;
    DWORD teSize = sizeof(TOKEN_ELEVATION);
    BOOL res = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &teSize);
    if (0 == res) {
        *exitTag = 3;
        goto exit;
    }

    DWORD tuSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tuSize);
    pTu = malloc(tuSize);
    if (NULL == pTu) {
        *exitTag = 4;
        goto exit;
    }
    res = GetTokenInformation(hToken, TokenUser, pTu, tuSize, &tuSize);
    if (0 == res) {
        *exitTag = 5;
        goto exit;
    }

    SID_NAME_USE snu;
    LookupAccountSidW(NULL, pTu->User.Sid, NULL, &dwNameSize, NULL, &dwDomainSize, &snu);

    name = malloc(dwNameSize * sizeof(WCHAR));
    domain = malloc(dwDomainSize * sizeof(WCHAR));
    res = LookupAccountSidW(NULL, pTu->User.Sid, name, &dwNameSize, domain, &dwDomainSize, &snu);
    if (0 == res) {
        *exitTag = 6;
        goto exit;
    }

    UserProfile *up = malloc(sizeof(*up));
    if (NULL == up) {
        *exitTag = 7;
        goto exit;
    }
 
    WCHAR *sidStr = NULL;
    res = ConvertSidToStringSidW(pTu->User.Sid, &sidStr);
    if (0 == res) {
        *exitTag = 8;
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
    if (0 != *exitTag) {
        if (NULL != name) {
            free(name); name = NULL;
        }
        if (NULL != domain) {
            free(domain); domain = NULL;
        }
        if (NULL != sidStr) {
            LocalFree(sidStr);
        }
        if (NULL != up) {
            free(up); up = NULL;
        }
    }

    return up;
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
    if (0 != *exitTag) {
        if (NULL != name) {
            free(name); name = NULL;
        }
        if (NULL != domain) {
            free(domain); domain = NULL;
        }
        if (NULL != sidStr) {
            LocalFree(sidStr);
        }
        if (NULL != up) {
            free(up); up = NULL;
        }
    }

    return up;
}

WCHAR *
GetCurrentExecutableFullName(DWORD *exitTag, DWORD *lastErrorCode) {
    WCHAR *fileName = malloc(MAX_NAME_PATH * sizeof(*fileName));
    if (NULL == fileName) {
        *exitTag = 1;
        return NULL;
    }

    DWORD size = GetModuleFileNameW(NULL, fileName, MAX_PATH);
    if (0 == size) {
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

    DWORD size = GetProcessImageFileNameW(hProcess, fileName, MAX_PATH);
    if (0 == size) {
        *exitTag = 2;
        *lastErrorCode = GetLastError();
        free(fileName);
        return NULL;
    }

    return fileName;
}

VOID
FreeOSProcesses(OSProcess *osprocs, DWORD n) {
    DWORD i;
    for (i = 0; i < n; i++) {
        free(osprocs[i].ExecName);
        FreeUserProfile(osprocs[i].UProfile);
    }
    free(osprocs);
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

    // Walkthrough a snapshot of all OS processes.
    if (Process32FirstW(snapshot, &process)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process.th32ProcessID);
            if (NULL == hProcess) {
                // Ignore the process.
                continue;
            }

            procs[i].PID = process.th32ProcessID;
            procs[i].PPID = process.th32ParentProcessID;
            procs[i].ExecName = GetProcessNameInDeviceForm(hProcess, exitTag, lastErrorCode);
            if (0 != *exitTag) {
                CloseHandle(hProcess);
                continue;
            }
            procs[i].UProfile = GetProcessUserProfile(hProcess, exitTag);
            if (0 != *exitTag) {
                free(procs[i].ExecName);
                FreeUserProfile(procs[i].UProfile);
                CloseHandle(hProcess);
                continue;
            }

            CloseHandle(hProcess);
            // Increment index only if OSProccesEx has been filled correctly.
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