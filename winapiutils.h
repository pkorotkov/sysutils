#ifndef WINAPIUTILS_H
#define WINAPIUTILS_H

// State target OS as Windows 7.
// https://msdn.microsoft.com/en-us/library/aa383745.aspx
#define _WIN32_WINNT 0x0601

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <mq.h>

#define MAX_NAME_PATH 256

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(HANDLE pHandle, DWORD pInformationClass, PVOID pInformation, DWORD pInformationLength, PDWORD ReturnLength);

typedef struct UserProfile {
    WCHAR *Name;
    WCHAR *Domain;
    WCHAR *SID;
    BOOL Elevated;
} UserProfile;

typedef struct OSProcess {
    DWORD PID;
    DWORD PPID;
    BOOL IsRemote;
    WCHAR *ExecName;
    WCHAR *CommandLine;
    UserProfile *UProfile;
} OSProcess;

UserProfile *
GetCurrentProcessUserProfile(DWORD *exitTag);

UserProfile *
GetProcessUserProfile(HANDLE hProcess, DWORD *exitTag);

VOID
FreeUserProfile(UserProfile *wup);

WCHAR *
GetCurrentExecutableFullName(DWORD *exitTag, DWORD *lastErrorCode);

WCHAR *
GetProcessNameInDeviceForm(HANDLE hProcess, DWORD *exitTag, DWORD *lastErrorCode);

OSProcess *
GetOSProcesses(DWORD *n, DWORD *exitTag, DWORD *lastErrorCode);

VOID
FreeOSProcesses(OSProcess *osprocs, DWORD n);

#endif /* WINAPIUTILS_H */
