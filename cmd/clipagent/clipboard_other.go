//go:build !windows && !darwin

package main

import "os"

// Live clipboard capture is implemented only on Windows and macOS. On any other
// platform (e.g. the Linux CI runner) the agent still builds and can enroll, but
// captures nothing — this keeps `go build ./...` working everywhere.

func getUsername() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

func newClipboardMonitor() ClipboardMonitor { return noopMonitor{} }

type noopMonitor struct{}

func (noopMonitor) Poll() *ClipboardSnapshot { return nil }

func clipboardProbe() (bool, string) {
	return false, "clipboard capture is only implemented on Windows and macOS"
}
