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

func CreateFile(name string, access, shareMode, creationDisposition, flagsAndAttributes uint32) (windows.Handle, error) {
	pName, err := syscall.UTF16FromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := procCreateFileW.Call(uintptr(unsafe.Pointer(&pName[0])), uintptr(access), uintptr(shareMode), 0, uintptr(creationDisposition), uintptr(flagsAndAttributes), 0)
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
