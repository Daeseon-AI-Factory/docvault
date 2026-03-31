package web

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SSEHub manages Server-Sent Events connections and broadcasts events to all connected clients.
type SSEHub struct {
	mu      sync.RWMutex
	clients map[*sseClient]bool
	logger  *slog.Logger
}

type sseClient struct {
	ch     chan SSEEvent
	userID int64
	role   string
}

// SSEEvent is a single event pushed to the dashboard.
type SSEEvent struct {
	Type      string      `json:"type"`      // "audit", "alert", "endpoint", "stats"
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewSSEHub(logger *slog.Logger) *SSEHub {
	return &SSEHub{
		clients: make(map[*sseClient]bool),
		logger:  logger,
	}
}

// ServeHTTP handles GET /api/events/stream — SSE endpoint.
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx passthrough

	client := &sseClient{
		ch: make(chan SSEEvent, 64),
	}

	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, client)
		h.mu.Unlock()
		close(client.ch)
	}()

	// Send initial heartbeat
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()

	// Heartbeat ticker to keep connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case event, ok := <-client.ch:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

// Broadcast sends an event to all connected SSE clients.
func (h *SSEHub) Broadcast(event SSEEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.ch <- event:
		default:
			// Client buffer full, skip (don't block)
			h.logger.Warn("SSE client buffer full, dropping event")
		}
	}
}

// BroadcastAuditLog pushes an audit log event to all dashboards.
func (h *SSEHub) BroadcastAuditLog(action, targetName, username, ip string) {
	h.Broadcast(SSEEvent{
		Type: "audit",
		Data: map[string]string{
			"action":      action,
			"target_name": targetName,
			"username":    username,
			"ip":          ip,
		},
	})
}

// BroadcastAlert pushes an alert event to all dashboards.
func (h *SSEHub) BroadcastAlert(severity, message, hostname string) {
	h.Broadcast(SSEEvent{
		Type: "alert",
		Data: map[string]string{
			"severity": severity,
			"message":  message,
			"hostname": hostname,
		},
	})
}

// BroadcastEndpointEvent pushes an endpoint event to all dashboards.
func (h *SSEHub) BroadcastEndpointEvent(eventType, hostname, fileName, processName string) {
	h.Broadcast(SSEEvent{
		Type: "endpoint",
		Data: map[string]string{
			"event_type":   eventType,
			"hostname":     hostname,
			"file_name":    fileName,
			"process_name": processName,
		},
	})
}

// ClientCount returns the number of connected SSE clients.
func (h *SSEHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
