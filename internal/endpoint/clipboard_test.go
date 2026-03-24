package endpoint

import (
	"encoding/json"
	"testing"
)

func TestNormalizeClipboardEventCopy(t *testing.T) {
	ce := &ClipboardEvent{
		Hostname:    "PC-DESIGN-003",
		Username:    "parkjs",
		Action:      "copy",
		Application: "Microsoft Word",
		ContentType: "text",
		ContentSize: 2048,
		Timestamp:   "2024-01-15T09:30:00Z",
	}

	hostnameMap := map[string]int64{
		"PC-DESIGN-003": 7,
	}

	event := NormalizeClipboardEvent(ce, hostnameMap)

	if event.EventType != EventClipCopy {
		t.Errorf("type = %s, want %s", event.EventType, EventClipCopy)
	}
	if event.Source != "clipboard" {
		t.Errorf("source = %s, want clipboard", event.Source)
	}
	if event.Hostname != "PC-DESIGN-003" {
		t.Errorf("hostname = %s", event.Hostname)
	}
	if event.UserID == nil || *event.UserID != 7 {
		t.Error("should map to user 7")
	}
	if event.ProcessName != "Microsoft Word" {
		t.Errorf("process = %s", event.ProcessName)
	}

	// Check detail JSON
	var detail map[string]interface{}
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if detail["content_size"] != float64(2048) {
		t.Errorf("detail.content_size = %v", detail["content_size"])
	}
}

func TestNormalizeClipboardEventPaste(t *testing.T) {
	ce := &ClipboardEvent{
		Hostname:    "PC-UNKNOWN",
		Action:      "paste",
		Application: "Notepad",
		ContentType: "text",
		ContentSize: 100,
		Timestamp:   "2024-01-15T10:00:00Z",
	}

	event := NormalizeClipboardEvent(ce, nil)

	if event.EventType != EventClipPaste {
		t.Errorf("type = %s, want %s", event.EventType, EventClipPaste)
	}
	if event.UserID != nil {
		t.Error("unknown host should have nil UserID")
	}
}

func TestNormalizeClipboardEventBadTimestamp(t *testing.T) {
	ce := &ClipboardEvent{
		Hostname:  "PC-001",
		Action:    "copy",
		Timestamp: "not-a-timestamp",
	}

	event := NormalizeClipboardEvent(ce, nil)

	// Should not panic, should use current time
	if event.EventTime.IsZero() {
		t.Error("event time should not be zero even with bad timestamp")
	}
}
