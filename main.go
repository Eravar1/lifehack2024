package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW = kernel32.NewProc("CreateFileW")
	procReadFile    = kernel32.NewProc("ReadFile")
	procWriteFile   = kernel32.NewProc("WriteFile")
	procCloseHandle = kernel32.NewProc("CloseHandle")
)

func CreateFile(
	name string,
	access uint32,
	shareMode uint32,
	securityAttributes *syscall.SecurityAttributes,
	creationDisposition uint32,
	flagsAndAttributes uint32,
	templateFile windows.Handle,
) (windows.Handle, error) {
	pName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pName)),
		uintptr(access),
		uintptr(shareMode),
		uintptr(unsafe.Pointer(securityAttributes)),
		uintptr(creationDisposition),
		uintptr(flagsAndAttributes),
		uintptr(templateFile),
	)
	if handle == uintptr(windows.InvalidHandle) {
		return windows.InvalidHandle, err
	}
	return windows.Handle(handle), nil
}

func main() {
	// fsnotify watcher start
	var statusLabel *walk.Label

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Read the PATHS_TO_MONITOR environment variable
	pathsToMonitor := os.Getenv("PATHS_TO_MONITOR")
	paths := strings.Split(pathsToMonitor, ";")

	// Create a new fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Add paths to the watcher
	for _, path := range paths {
		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}
	}
	// fsnotify watcher end

	// Create and initialize the main window
	var mw *walk.MainWindow
	if err := (MainWindow{
		AssignTo: &mw,
		Title:    "Ransomware Detection App",
		Size:     Size{Width: 400, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			// Add widgets (controls) to the main window
			Label{
				AssignTo: &statusLabel,
				Text:     "Welcome to the Ransomware Detection App!",
			},
			PushButton{
				Text:      "Clickable Button",
				OnClicked: detectRansomware,
			},
		},
	}.Create()); err != nil {
		log.Fatal(err)
	}

	// Monitor events
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Check for suspicious activity
				if isSuspiciousActivity(event) {
					// Update the GUI
					mw.Synchronize(func() {
						statusLabel.SetText(fmt.Sprintf("Suspicious activity detected: %s", event.Name))
					})

					// Alert the user and provide an option to terminate the process
					walk.MsgBox(mw, "Alert", "Suspicious activity detected! Terminate the process?", walk.MsgBoxYesNo|walk.MsgBoxIconWarning)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Error:", err)
			}
		}
	}()

	// Run the main window
	mw.Run()
}

// detectRansomware handles the "Detect Ransomware" button click event
func detectRansomware() {
	// Placeholder function for ransomware detection logic
	log.Println("Button clicked")
	// Implement your ransomware detection logic here
}

// isSuspiciousActivity checks for suspicious file events
func isSuspiciousActivity(event fsnotify.Event) bool {
	if event.Op&fsnotify.Write == fsnotify.Write {
		// Example check: files with specific extensions or names
		if strings.HasSuffix(event.Name, ".exe") || strings.Contains(event.Name, "ransom") {
			return true
		}
	}
	return false
}
