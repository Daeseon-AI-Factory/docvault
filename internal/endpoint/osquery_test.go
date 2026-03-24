package endpoint

import (
	"testing"
)

func TestNormalizeOsqueryEvents(t *testing.T) {
	batch := &OsqueryBatch{
		NodeKey: "test-key",
		Results: []OsqueryResult{
			{
				Name:           "file_events",
				HostIdentifier: "PC-ENG-001",
				UnixTime:       1700000000,
				Action:         "CREATED",
				Columns: map[string]string{
					"target_path": "C:\\Users\\kim\\Documents\\design.dwg",
					"process":     "AutoCAD.exe",
				},
			},
			{
				Name:           "file_events",
				HostIdentifier: "PC-ENG-001",
				UnixTime:       1700000010,
				Action:         "DELETED",
				Columns: map[string]string{
					"target_path": "C:\\Temp\\secret.pdf",
					"process":     "explorer.exe",
				},
			},
			{
				Name:           "usb_devices",
				HostIdentifier: "PC-ENG-002",
				UnixTime:       1700000020,
				Action:         "added",
				Columns: map[string]string{
					"vendor": "SanDisk",
					"model":  "Ultra USB 3.0",
				},
			},
			{
				Name:           "process_events",
				HostIdentifier: "PC-ENG-001",
				UnixTime:       1700000030,
				Action:         "exec",
				Columns: map[string]string{
					"path":    "C:\\Windows\\System32\\cmd.exe",
					"cmdline": "cmd.exe /c copy secret.pdf E:\\",
				},
			},
		},
	}

	hostnameMap := map[string]int64{
		"PC-ENG-001": 42,
	}

	events := NormalizeOsqueryEvents(batch, hostnameMap)

	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// Event 1: file write
	e := events[0]
	if e.EventType != EventFileWrite {
		t.Errorf("event[0] type = %s, want %s", e.EventType, EventFileWrite)
	}
	if e.Hostname != "PC-ENG-001" {
		t.Errorf("event[0] hostname = %s", e.Hostname)
	}
	if e.UserID == nil || *e.UserID != 42 {
		t.Error("event[0] should map to user 42")
	}
	if e.ProcessName != "AutoCAD.exe" {
		t.Errorf("event[0] process = %s", e.ProcessName)
	}
	if e.Source != "osquery" {
		t.Errorf("event[0] source = %s", e.Source)
	}

	// Event 2: file delete
	if events[1].EventType != EventFileDelete {
		t.Errorf("event[1] type = %s, want %s", events[1].EventType, EventFileDelete)
	}

	// Event 3: USB mount (no user mapping for PC-ENG-002)
	if events[2].EventType != EventUSBMount {
		t.Errorf("event[2] type = %s, want %s", events[2].EventType, EventUSBMount)
	}
	if events[2].UserID != nil {
		t.Error("event[2] should have nil UserID (unknown host)")
	}

	// Event 4: process exec
	if events[3].EventType != EventProcessExec {
		t.Errorf("event[3] type = %s, want %s", events[3].EventType, EventProcessExec)
	}
}

func TestMapOsqueryAction(t *testing.T) {
	tests := []struct {
		query  string
		action string
		want   EventType
	}{
		{"file_events", "CREATED", EventFileWrite},
		{"file_events", "UPDATED", EventFileWrite},
		{"file_events", "DELETED", EventFileDelete},
		{"file_events", "MOVED", EventFileRename},
		{"file_events", "ACCESSED", EventFileOpen},
		{"usb_devices", "added", EventUSBMount},
		{"process_events", "exec", EventProcessExec},
		{"unknown_query", "something", EventType("unknown_query.something")},
	}

	for _, tt := range tests {
		t.Run(tt.query+"/"+tt.action, func(t *testing.T) {
			got := mapOsqueryAction(tt.query, tt.action)
			if got != tt.want {
				t.Errorf("mapOsqueryAction(%s, %s) = %s, want %s", tt.query, tt.action, got, tt.want)
			}
		})
	}
}

func TestNormalizeOsqueryEventsEmptyBatch(t *testing.T) {
	batch := &OsqueryBatch{Results: []OsqueryResult{}}
	events := NormalizeOsqueryEvents(batch, nil)
	if len(events) != 0 {
		t.Errorf("empty batch should produce 0 events, got %d", len(events))
	}
}
