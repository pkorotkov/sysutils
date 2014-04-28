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
	PID         int
	PPID        int
	ExecName    string
	CommandLine string
	UProfile    UserProfile
}

func intToBool(i int) bool {
	return i != 0
}

func GetOSProcesses() ([]OSProcess, error) {
	var (
		procs  *C.OSProcess
		n      C.DWORD
		eTag   C.DWORD
		leCode C.DWORD
	)
	procs = C.GetOSProcesses((*C.DWORD)(unsafe.Pointer(&n)), (*C.DWORD)(unsafe.Pointer(&eTag)), (*C.DWORD)(unsafe.Pointer(&leCode)))
	if et := uint32(eTag); et != 0 {
		return nil, fmt.Errorf("C.GetOSProcesses: exit tag %d; last error code %d", et, int32(leCode))
	}
	defer C.FreeOSProcesses((*C.OSProcess)(unsafe.Pointer(procs)), n)

	var procEntries []C.OSProcess
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&procEntries)))
	sliceHeader.Cap = int(n)
	sliceHeader.Len = sliceHeader.Cap
	sliceHeader.Data = uintptr(unsafe.Pointer(procs))

	var rprocs []OSProcess
	for _, pe := range procEntries {
		up := UserProfile{
			WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(pe.UProfile.Name))),
			WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(pe.UProfile.Domain))),
			WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(pe.UProfile.SID))),
			intToBool(int(pe.UProfile.Elevated)),
		}
		osp := OSProcess{
			int(pe.PID),
			int(pe.PPID),
			WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(pe.ExecName))),
			WCHARPtrToGoString((*C.WCHAR)(unsafe.Pointer(pe.CommandLine))),
			up,
		}
		rprocs = append(rprocs, osp)
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
	var eTag, leCode C.DWORD
	var fn *C.WCHAR = C.GetCurrentExecutableFullName((*C.DWORD)(unsafe.Pointer(&eTag)), (*C.DWORD)(unsafe.Pointer(&leCode)))
	defer C.free(unsafe.Pointer(fn))

	if et := int32(eTag); et != 0 {
		return "", "", fmt.Errorf("C.GetCurrentExecutableFullName: exit tag %d; last error code %d", et, int32(leCode))
	}
	d, n := filepath.Split(WCHARPtrToGoString(fn))

	return d, n, nil

}

type UserProfile struct {
	Name       string
	Domain     string
	SID        string
	IsElevated bool
}

func GetCurrentProcessUserProfile() (*UserProfile, error) {
	var eTag C.DWORD
	up, err := C.GetCurrentProcessUserProfile((*C.DWORD)(unsafe.Pointer(&eTag)))
	if err != nil {
		return nil, err
	}
	if et := uint32(eTag); et != 0 {
		return nil, fmt.Errorf("C.GetCurrentUserProfile: exit tag %d", et)
	}
	defer C.FreeUserProfile(up)

	gup := new(UserProfile)
	gup.Name = WCHARPtrToGoString(up.Name)
	gup.Domain = WCHARPtrToGoString(up.Domain)
	gup.SID = WCHARPtrToGoString(up.SID)
	gup.IsElevated = intToBool(int(up.Elevated))

	return gup, nil
}

func HasCurrentProcessAdminPrivileges() (bool, error) {
	wup, err := GetCurrentProcessUserProfile()
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
