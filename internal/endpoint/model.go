package endpoint

import (
	"encoding/json"
	"time"
)

type EventType string

const (
	EventFileOpen    EventType = "file_open"
	EventFileWrite   EventType = "file_write"
	EventFileDelete  EventType = "file_delete"
	EventFileRename  EventType = "file_rename"
	EventFileCopy    EventType = "file_copy"
	EventUSBMount    EventType = "usb_mount"
	EventUSBCopy     EventType = "usb_copy"
	EventClipCopy    EventType = "clipboard_copy"
	EventClipPaste   EventType = "clipboard_paste"
	EventPrintJob    EventType = "print_job"
	EventProcessExec EventType = "process_exec"
)

type EndpointEvent struct {
	ID          int64           `json:"id"`
	UserID      *int64          `json:"user_id,omitempty"`
	Hostname    string          `json:"hostname"`
	EventType   EventType       `json:"event_type"`
	FileName    string          `json:"file_name"`
	FilePath    string          `json:"file_path"`
	ProcessName string          `json:"process_name"`
	Detail      json.RawMessage `json:"detail,omitempty"`
	Source      string          `json:"source"`
	EventTime   time.Time       `json:"event_time"`
	ReceivedAt  time.Time       `json:"received_at"`
}
