package winutils

/*
#include "winapiutils.h"
*/
import "C"

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func UTF16PtrToGoString(cstr *uint16) string {
	if cstr != nil {
		us := make([]uint16, 0, 256)
		for p := uintptr(unsafe.Pointer(cstr)); ; p += 2 {
			u := *(*uint16)(unsafe.Pointer(p))
			if u == 0 {
				return string(utf16.Decode(us))
			}
			us = append(us, u)
		}
	}

	return ""
}

func WCHARPtrToGoString(wstr *C.WCHAR) string {
	return UTF16PtrToGoString((*uint16)(wstr))
}

func GoStringToLPCWSTR(s string) C.LPCWSTR {
	return (C.LPCWSTR)(unsafe.Pointer(syscall.StringToUTF16Ptr(s)))
}

func GoStringToLPWSTR(s string) C.LPWSTR {
	return (C.LPWSTR)(unsafe.Pointer(syscall.StringToUTF16Ptr(s)))
}
