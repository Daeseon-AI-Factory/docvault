package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// ClipboardEvent is the payload sent to the server.
type ClipboardEvent struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Action      string `json:"action"`       // "copy"
	Application string `json:"application"`  // source app
	ContentType string `json:"content_type"` // "text", "files", "image"
	ContentSize int    `json:"content_size"`
	WindowTitle string `json:"window_title"`
	Timestamp   string `json:"timestamp"`
}

// ClipboardMonitor is implemented per-platform (Windows/macOS).
type ClipboardMonitor interface {
	// Poll checks for clipboard changes. Returns nil if no change.
	Poll() *ClipboardSnapshot
}

// ClipboardSnapshot holds a single clipboard state observation.
type ClipboardSnapshot struct {
	ContentType string
	ContentSize int
	AppName     string
	WindowTitle string
}

func runMonitor() {
	serverURL := os.Getenv("DOCVAULT_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	psk := os.Getenv("DOCVAULT_AGENT_PSK")
	hostname, _ := os.Hostname()
	username := getUsername()

	log.Printf("DocVault clipboard agent starting on %s (user: %s)", hostname, username)
	log.Printf("Reporting to %s", serverURL)

	client := &http.Client{Timeout: 10 * time.Second}
	enrollAgent(client, serverURL, psk, hostname, username)

	monitor := newClipboardMonitor()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-quit:
			log.Println("shutting down clipboard agent")
			return
		case <-ticker.C:
			snap := monitor.Poll()
			if snap == nil {
				continue
			}

			event := &ClipboardEvent{
				Hostname:    hostname,
				Username:    username,
				Action:      "copy",
				Application: snap.AppName,
				ContentType: snap.ContentType,
				ContentSize: snap.ContentSize,
				WindowTitle: snap.WindowTitle,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			}

			go sendEvent(client, serverURL, psk, event)
		}
	}
}

func enrollAgent(client *http.Client, serverURL, psk, hostname, username string) {
	payload, _ := json.Marshal(map[string]string{
		"hostname": hostname,
		"username": username,
		"source":   "clipboard",
	})

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/enroll", bytes.NewReader(payload))
	if err != nil {
		log.Printf("enroll request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if psk != "" {
		req.Header.Set("X-Agent-PSK", psk)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("enroll error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Println("enrolled successfully with server")
	} else {
		log.Printf("enrollment returned status %d", resp.StatusCode)
	}
}

func sendEvent(client *http.Client, serverURL, psk string, event *ClipboardEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/events/clipboard", bytes.NewReader(body))
	if err != nil {
		log.Printf("request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if psk != "" {
		req.Header.Set("X-Agent-PSK", psk)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("server returned %d", resp.StatusCode)
		return
	}

	fmt.Printf(".")
}
