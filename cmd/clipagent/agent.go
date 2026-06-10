package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	pollInterval    = 500 * time.Millisecond // clipboard poll cadence
	enrollInterval  = 5 * time.Minute        // periodic re-enroll (covers server restarts / IP changes)
	eventQueueSize  = 500                     // bounded in-memory buffer when the server is unreachable
	maxSendAttempts = 4                       // attempts per event before giving up
	initialBackoff  = 1 * time.Second         // first retry delay; doubles each attempt
	flushTimeout    = 5 * time.Second         // how long to drain the queue on shutdown
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
	if psk == "" {
		log.Println("WARNING: DOCVAULT_AGENT_PSK is not set — the server will reject events if it requires a PSK")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Bounded queue decouples polling from the network. If the server is briefly
	// unreachable, events buffer here and the sender retries them with backoff.
	queue := make(chan *ClipboardEvent, eventQueueSize)
	var wg sync.WaitGroup

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Sender goroutine: drains the queue, retrying each event.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range queue {
			sendEventWithRetry(client, serverURL, psk, event)
		}
	}()

	// Enroll now, then periodically — re-enrollment survives server restarts and
	// host/IP changes without manual intervention.
	enrollAgent(client, serverURL, psk, hostname, username)
	enrollTicker := time.NewTicker(enrollInterval)
	defer enrollTicker.Stop()

	monitor := newClipboardMonitor()
	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-quit:
			log.Println("shutting down clipboard agent — flushing queued events")
			close(queue)
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
				log.Println("all queued events flushed")
			case <-time.After(flushTimeout):
				log.Println("flush timeout — some events may be unsent")
			}
			return

		case <-enrollTicker.C:
			enrollAgent(client, serverURL, psk, hostname, username)

		case <-pollTicker.C:
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

			enqueue(queue, event)
		}
	}
}

// enqueue adds an event without blocking the poll loop. If the queue is full
// (server down for a while), it drops the oldest event to bound memory.
func enqueue(queue chan *ClipboardEvent, event *ClipboardEvent) {
	select {
	case queue <- event:
		return
	default:
	}
	// Full: drop oldest, then enqueue the new one.
	select {
	case <-queue:
	default:
	}
	select {
	case queue <- event:
	default:
	}
	log.Println("event queue full — dropped the oldest event")
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
		log.Println("enrolled with server")
	} else {
		log.Printf("enrollment returned status %d", resp.StatusCode)
	}
}

// sendEventWithRetry attempts delivery up to maxSendAttempts times with
// exponential backoff before giving up on a single event.
func sendEventWithRetry(client *http.Client, serverURL, psk string, event *ClipboardEvent) {
	backoff := initialBackoff
	for attempt := 1; attempt <= maxSendAttempts; attempt++ {
		if err := sendEvent(client, serverURL, psk, event); err == nil {
			return
		} else if attempt == maxSendAttempts {
			log.Printf("dropping event after %d attempts: %v", maxSendAttempts, err)
			return
		}
		time.Sleep(backoff)
		backoff *= 2
	}
}

func sendEvent(client *http.Client, serverURL, psk string, event *ClipboardEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/events/clipboard", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if psk != "" {
		req.Header.Set("X-Agent-PSK", psk)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
