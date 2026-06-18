//go:build darwin

package main

import (
	"log"
)

func platformMain() {
	log.Println("Running in console mode (launchd service available for macOS)")
	runMonitor()
}

func agentRunningMode() string { return "interactive_user" }
