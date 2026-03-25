package endpoint

import (
	"encoding/json"
	"time"
)

// ClipboardEvent represents a clipboard monitoring event from the agent.
type ClipboardEvent struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Action      string `json:"action"`       // "copy" or "paste"
	Application string `json:"application"`   // process name (e.g., "KakaoTalk.exe")
	ContentType string `json:"content_type"`  // "text", "files", "image"
	ContentSize int    `json:"content_size"`
	WindowTitle string `json:"window_title"`  // full window title for context
	Timestamp   string `json:"timestamp"`
}

// NormalizeClipboardEvent converts a clipboard event into an EndpointEvent.
func NormalizeClipboardEvent(ce *ClipboardEvent, hostnameUserMap map[string]int64) *EndpointEvent {
	eventType := EventClipCopy
	if ce.Action == "paste" {
		eventType = EventClipPaste
	}

	eventTime, err := time.Parse(time.RFC3339, ce.Timestamp)
	if err != nil {
		eventTime = time.Now()
	}

	event := &EndpointEvent{
		Hostname:    ce.Hostname,
		EventType:   eventType,
		ProcessName: ce.Application,
		Source:      "clipboard",
		EventTime:   eventTime,
	}

	if userID, ok := hostnameUserMap[ce.Hostname]; ok {
		event.UserID = &userID
	}

	detail := map[string]interface{}{
		"content_type": ce.ContentType,
		"content_size": ce.ContentSize,
		"application":  ce.Application,
		"window_title": ce.WindowTitle,
	}
	if d, err := json.Marshal(detail); err == nil {
		event.Detail = d
	}

	return event
}
