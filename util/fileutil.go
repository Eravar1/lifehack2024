package util

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/windows"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW = kernel32.NewProc("CreateFileW")
)

func CreateFile(name string, access uint32, shareMode uint32, securityAttributes *syscall.SecurityAttributes, creationDisposition uint32, flagsAndAttributes uint32, templateFile windows.Handle) (windows.Handle, error) {
	pName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := procCreateFileW.Call(uintptr(unsafe.Pointer(pName)), uintptr(access), uintptr(shareMode), uintptr(unsafe.Pointer(securityAttributes)), uintptr(creationDisposition), uintptr(flagsAndAttributes), uintptr(templateFile))
	if handle == uintptr(windows.InvalidHandle) {
		return windows.InvalidHandle, err
	}
	return windows.Handle(handle), nil
}

func IsSuspiciousActivity(event fsnotify.Event) bool {
	if event.Op&fsnotify.Write == fsnotify.Write {
		if strings.HasSuffix(event.Name, ".exe") || strings.Contains(event.Name, "ransom") {
			return true
		}
	}
	return false
}
