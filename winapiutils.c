#include "winapiutils.h"

/*
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
*/

VOID
FreeWinUserProfile(WinUserProfile *wup) {
    free(wup->Name);
    free(wup->Domain);
    LocalFree(wup->SID);
    free(wup);
}

WinUserProfile *
GetWinUserProfile(DWORD *exitTag) {
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

    WinUserProfile *wup = malloc(sizeof(*wup));
    if (NULL == wup) {
        *exitTag = 7;
        goto exit;
    }
 
    WCHAR *sidStr = NULL;
    res = ConvertSidToStringSidW(pTu->User.Sid, &sidStr);
    if (0 == res) {
        *exitTag = 8;
        goto exit;
    }
    wup->Name = name;
    wup->Domain = domain;
    wup->SID = sidStr;
    wup->Elevated = elevation.TokenIsElevated;

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
        // Q: Check for nullity as well?
        LocalFree(sidStr);
        if (NULL != wup) {
            free(wup); wup = NULL;
        }
    }

    return wup;
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