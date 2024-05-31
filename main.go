package main

import (
	"log"

	"./monitoring"
	"./ui"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Start the monitoring and UI components
	go monitoring.Start()
	ui.Start()
}
