package main

import (
	"log"

	"github.com/Eravar1/lifehack2024/monitoring"
	"github.com/Eravar1/lifehack2024/ui"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Start the monitoring and UI components
	go monitoring.Start()
	monitoring.DemoCreateFile()
	ui.Start()
}
