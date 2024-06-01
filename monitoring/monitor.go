package monitoring

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Eravar1/lifehack2024/util"
	"golang.org/x/sys/windows"
)

const (
	FILE_NOTIFY_CHANGE_FILE_NAME   = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME    = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES  = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE        = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE  = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION    = 0x00000040
	FILE_NOTIFY_CHANGE_SECURITY    = 0x00000100

	FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
	FILE_LIST_DIRECTORY        = 0x0001
)

func monitorDirectory(path string) {
	pPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		log.Fatalf("Error converting path: %v", err)
	}

	handle, err := windows.CreateFile(pPath,
		FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err != nil {
		log.Fatalf("Error creating handle: %v", err)
	}
	defer windows.CloseHandle(handle)

	buffer := make([]byte, 4096)
	overlapped := new(windows.Overlapped)
	var dummy uintptr

	for {
		var bytesReturned uint32
		err := windows.ReadDirectoryChanges(handle,
			&buffer[0],
			uint32(len(buffer)),
			true,
			FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|FILE_NOTIFY_CHANGE_ATTRIBUTES|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE|FILE_NOTIFY_CHANGE_LAST_ACCESS|FILE_NOTIFY_CHANGE_CREATION|FILE_NOTIFY_CHANGE_SECURITY,
			&bytesReturned,
			overlapped,
			dummy)
		if err != nil {
			log.Printf("Error reading directory changes: %v", err)
			return
		}

		offset := 0
		for {
			if offset >= int(bytesReturned) {
				break
			}

			notification := (*windows.FileNotifyInformation)(unsafe.Pointer(&buffer[offset]))
			name := syscall.UTF16ToString((*[syscall.MAX_PATH]uint16)(unsafe.Pointer(&notification.FileName))[:notification.FileNameLength/2])
			log.Printf("File accessed: %s", name)

			if notification.NextEntryOffset == 0 {
				break
			}
			offset += int(notification.NextEntryOffset)
		}
	}
}

func Start() {
	pathsToMonitor := os.Getenv("PATHS_TO_MONITOR")
	paths := strings.Split(pathsToMonitor, ";")

	for _, path := range paths {
		go monitorDirectory(path)
	}

	// Keeping the main goroutine alive
	select {}
}

func DemoCreateFile() {
	// Example usage of CreateFile
	pathsToMonitor := os.Getenv("PATHS_TO_MONITOR")
	paths := strings.Split(pathsToMonitor, ";")
	path := paths[0] + "\\example.txt"

	handle, err := util.CreateFile(path, syscall.GENERIC_READ, 0, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		log.Println("Error creating file:", err)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(handle))
	log.Println("File created successfully")
}
