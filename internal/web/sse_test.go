package web

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestSSEHubBroadcast(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := NewSSEHub(logger)

	if hub.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", hub.ClientCount())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "/api/events/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		hub.ServeHTTP(rec, req)
		close(done)
	}()

	waitUntil(t, func() bool { return hub.ClientCount() == 1 })

	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", rec.Header().Get("Content-Type"))
	}
	if body := rec.Body.String(); !strings.Contains(body, "event: connected") {
		t.Errorf("expected connected event, got: %s", body)
	}

	hub.BroadcastAuditLog("file.upload", "test.dwg", "admin", "192.168.1.1")
	waitUntil(t, func() bool {
		body := rec.Body.String()
		return strings.Contains(body, "event: audit") && strings.Contains(body, "test.dwg")
	})

	cancel()
	waitUntil(t, func() bool { return hub.ClientCount() == 0 })
	<-done
}

func TestSSEHubMultipleClients(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := NewSSEHub(logger)

	cancels := make([]context.CancelFunc, 3)
	done := make([]chan struct{}, 3)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		req := httptest.NewRequest("GET", "/api/events/stream", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		done[i] = make(chan struct{})
		go func(ch chan struct{}) {
			hub.ServeHTTP(rec, req)
			close(ch)
		}(done[i])
	}
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()

	waitUntil(t, func() bool { return hub.ClientCount() == 3 })

	cancels[0]()
	waitUntil(t, func() bool { return hub.ClientCount() == 2 })

	hub.BroadcastAlert("high", "USB device detected", "PC-001")

	cancels[1]()
	cancels[2]()
	for _, ch := range done {
		<-ch
	}
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
