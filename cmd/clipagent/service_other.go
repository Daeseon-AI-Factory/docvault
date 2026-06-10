//go:build !windows && !darwin

package main

import "log"

func platformMain() {
	log.Println("DocVault clipboard agent: live capture is supported on Windows and macOS only")
	runMonitor()
}
