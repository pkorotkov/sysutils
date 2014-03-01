#ifndef WINAPIUTILS_H
#define WINAPIUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>
#include <windows.h>
#include <tlhelp32.h>

#define MAX_NAME_PATH 256

BOOL
IsElevated(void);

WCHAR *
GetExecutableFullName(DWORD *exitTag);

PROCESSENTRY32W *
GetOSProcesses(DWORD *n, DWORD *exitTag);

#endif /* WINAPIUTILS_H */