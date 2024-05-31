package monitoring

import (
	"log"
	"os"
	"strings"

	"github.com/Eravar1/lifehack2024/util"
	"github.com/fsnotify/fsnotify"
)

func Start() {
	pathsToMonitor := os.Getenv("PATHS_TO_MONITOR")
	paths := strings.Split(pathsToMonitor, ";")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	for _, path := range paths {
		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if util.IsSuspiciousActivity(event) {
				// Handle suspicious activity
				log.Println("Suspicious activity detected:", event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error:", err)
		}
	}
}
