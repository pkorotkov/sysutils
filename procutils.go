package winutils

/*
#include "winapiutils.h"
*/
import "C"

import (
	"fmt"
	"path/filepath"
	"reflect"
	"unsafe"
)

type OSProcess struct {
	PID      int
	ExecName string
}

func GetOSProcesses() ([]OSProcess, error) {
	var (
		procs *C.PROCESSENTRY32W
		n     C.DWORD
		eTag  C.DWORD
	)
	procs = C.GetOSProcesses((*C.DWORD)(unsafe.Pointer(&n)), (*C.DWORD)(unsafe.Pointer(&eTag)))
	if et := uint32(eTag); et != 0 {
		return nil, fmt.Errorf("C.GetOSProcesses exit tag is non-zero: %d", et)
	}
	defer C.free(unsafe.Pointer(procs))

	var procEntries []C.PROCESSENTRY32W
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&procEntries)))
	sliceHeader.Cap = int(n)
	sliceHeader.Len = sliceHeader.Cap
	sliceHeader.Data = uintptr(unsafe.Pointer(procs))

	var rprocs []OSProcess
	for _, pe := range procEntries {
		rprocs = append(rprocs, OSProcess{int(pe.th32ProcessID), WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(&pe.szExeFile[0])))})
	}

	return rprocs, nil
}

func GetCurrentProcessID() int {
	return int(C.GetCurrentProcessId())
}

func IsProcessByNameAlone(name string) (bool, error) {
	procs, err := GetOSProcesses()
	if err != nil {
		return false, err
	}

	pc := 0
	for _, p := range procs {
		if name == p.ExecName {
			pc++
		}
	}

	return pc == 1, nil
}

func ProcessByNameExists(name string) (bool, error) {
	procs, err := GetOSProcesses()
	if err != nil {
		return false, err
	}

	pc := 0
	for _, p := range procs {
		if name == p.ExecName {
			pc++
		}
	}

	return pc != 0, nil
}

func ProcessByNameAndPIDExists(name string, pid int) (bool, error) {
	procs, err := GetOSProcesses()
	if err != nil {
		return false, err
	}

	for _, p := range procs {
		if name == p.ExecName && pid == p.PID {
			return true, nil
		}
	}

	return false, nil
}

func GetThisExecutableDirAndName() (string, string, error) {
	var eTag C.DWORD
	var fn *C.WCHAR = C.GetExecutableFullName((*C.DWORD)(unsafe.Pointer(&eTag)))
	defer C.free(unsafe.Pointer(fn))

	if et := int32(eTag); et != 0 {
		return "", "", fmt.Errorf("C.GetExecutableFullName: Error code (last error code) %d", et)
	}
	d, n := filepath.Split(WCHARPtrToGoString(fn))
	
	return d, n, nil
	
}

type WinUserProfile struct {
	Name       string
	Domain     string
	SID        string
	IsElevated bool
}

func GetWinUserProfile() (*WinUserProfile, error) {
	var eTag C.DWORD
	wup, err := C.GetWinUserProfile((*C.DWORD)(unsafe.Pointer(&eTag)))
	if err != nil {
		return nil, err
	}
	if et := uint32(eTag); et != 0 {
		return nil, fmt.Errorf("C.GetWinUserProfile exit tag is non-zero: %d", et)
	}
	defer C.FreeWinUserProfile(wup)

	gwup := new(WinUserProfile)
	gwup.Name = WCHARPtrToGoString(wup.Name)
	gwup.Domain = WCHARPtrToGoString(wup.Domain)
	gwup.SID = WCHARPtrToGoString(wup.SID)
	if int(wup.Elevated) == 0 {
		gwup.IsElevated = false
	} else {
		gwup.IsElevated = true
	}

	return gwup, nil
}

func HasProcessAdminPrivileges() (bool, error) {
	wup, err := GetWinUserProfile()
	if err != nil {
		return false, err
	}
	
	return wup.IsElevated, nil
}

func HideConsoleWindow() (err error) {
	_, err = C.FreeConsole()
	if err != nil {
		return
	}
	_, err = C.AllocConsole()
	if err != nil {
		return
	}
	hwnd, err := C.GetConsoleWindow()
	if err != nil {
		return
	}
	_, err = C.ShowWindow(hwnd, C.SW_HIDE)
	if err != nil {
		return
	}

	return
}
