#ifndef WINAPIUTILS_H
#define WINAPIUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>
#include <windows.h>
#include <tlhelp32.h>
#include <mq.h>

#define MAX_NAME_PATH 256

typedef struct WinUserProfile {
    WCHAR *Name;
    WCHAR *Domain;
    WCHAR *SID;
    BOOL Elevated;
} WinUserProfile;

VOID
FreeWinUserProfile(WinUserProfile *wup);

WinUserProfile *
GetWinUserProfile(DWORD *exitTag);

WCHAR *
GetExecutableFullName(DWORD *exitTag);

PROCESSENTRY32W *
GetOSProcesses(DWORD *n, DWORD *exitTag);

#endif /* WINAPIUTILS_H */