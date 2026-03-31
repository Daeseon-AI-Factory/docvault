package web

import (
	"bufio"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSSEHubBroadcast(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := NewSSEHub(logger)

	if hub.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", hub.ClientCount())
	}

	// Start SSE server
	server := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer server.Close()

	// Connect client
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("connect error: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", resp.Header.Get("Content-Type"))
	}

	reader := bufio.NewReader(resp.Body)

	// Read initial "connected" event
	line, _ := reader.ReadString('\n') // "event: connected\n"
	if !strings.Contains(line, "connected") {
		t.Errorf("expected connected event, got: %s", line)
	}
	reader.ReadString('\n') // "data: ...\n"
	reader.ReadString('\n') // "\n"

	// Wait for client to register
	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", hub.ClientCount())
	}

	// Broadcast an event
	hub.BroadcastAuditLog("file.upload", "test.dwg", "admin", "192.168.1.1")

	// Read the broadcasted event
	eventLine, _ := reader.ReadString('\n') // "event: audit\n"
	if !strings.Contains(eventLine, "audit") {
		t.Errorf("expected audit event, got: %s", eventLine)
	}

	dataLine, _ := reader.ReadString('\n') // "data: {...}\n"
	if !strings.Contains(dataLine, "test.dwg") {
		t.Errorf("expected test.dwg in data, got: %s", dataLine)
	}
}

func TestSSEHubMultipleClients(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := NewSSEHub(logger)

	server := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer server.Close()

	// Connect 3 clients
	clients := make([]*http.Response, 3)
	for i := 0; i < 3; i++ {
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("client %d connect error: %v", i, err)
		}
		clients[i] = resp
	}
	defer func() {
		for _, c := range clients {
			c.Body.Close()
		}
	}()

	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 3 {
		t.Errorf("expected 3 clients, got %d", hub.ClientCount())
	}

	// Close one client
	clients[0].Body.Close()
	time.Sleep(50 * time.Millisecond)

	// Broadcast should still work for remaining clients
	hub.BroadcastAlert("high", "USB device detected", "PC-001")
}

func TestSSEHubBroadcastTypes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := NewSSEHub(logger)

	// Test that broadcasts don't panic with no clients
	hub.BroadcastAuditLog("login", "", "admin", "10.0.0.1")
	hub.BroadcastAlert("critical", "extension disguise", "PC-007")
	hub.BroadcastEndpointEvent("usb_copy", "PC-003", "secret.dwg", "explorer.exe")
	hub.Broadcast(SSEEvent{Type: "stats", Data: map[string]int{"total": 100}})

	if hub.ClientCount() != 0 {
		t.Error("should have 0 clients")
	}
}
