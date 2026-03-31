//go:build darwin

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

type darwinMonitor struct {
	lastHash string
}

func newClipboardMonitor() ClipboardMonitor {
	return &darwinMonitor{}
}

func (m *darwinMonitor) Poll() *ClipboardSnapshot {
	// pbpaste outputs the current clipboard text content
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return nil
	}

	// Hash to detect changes without storing content
	hash := fmt.Sprintf("%x", sha256.Sum256(out))
	if hash == m.lastHash {
		return nil
	}
	m.lastHash = hash

	contentSize := len(out)
	if contentSize == 0 {
		return nil
	}

	contentType := "text"
	// Check if clipboard contains file paths (macOS drag-and-drop copies paths)
	content := string(out)
	if looksLikeFilePaths(content) {
		contentType = "files"
	}

	// Get frontmost application via AppleScript
	appName := getFrontmostApp()

	return &ClipboardSnapshot{
		ContentType: contentType,
		ContentSize: contentSize,
		AppName:     appName,
		WindowTitle: appName, // macOS doesn't expose window titles easily without accessibility APIs
	}
}

func getUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

// getFrontmostApp uses AppleScript to get the name of the frontmost application.
func getFrontmostApp() string {
	out, err := exec.Command("osascript", "-e",
		`tell application "System Events" to get name of first application process whose frontmost is true`).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// looksLikeFilePaths checks if clipboard content looks like one or more file paths.
func looksLikeFilePaths(content string) bool {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) == 0 {
		return false
	}
	// If every non-empty line starts with / it's likely file paths
	pathCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") || strings.HasPrefix(line, "~") {
			pathCount++
		}
	}
	return pathCount > 0 && pathCount == len(lines)
}
