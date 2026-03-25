package endpoint

import (
	"encoding/json"
	"time"
)

type EventType string

const (
	// File operations
	EventFileOpen    EventType = "file_open"
	EventFileWrite   EventType = "file_write"
	EventFileDelete  EventType = "file_delete"
	EventFileRename  EventType = "file_rename"
	EventFileCopy    EventType = "file_copy"
	EventExtChanged  EventType = "extension_changed" // 확장자 변경 탐지

	// Removable/network storage
	EventUSBMount      EventType = "usb_mount"
	EventUSBCopy       EventType = "usb_copy"        // USB 드라이브에 파일 복사
	EventNetShareCopy  EventType = "netshare_copy"    // 네트워크 공유 폴더에 파일 복사

	// Clipboard
	EventClipCopy    EventType = "clipboard_copy"
	EventClipPaste   EventType = "clipboard_paste"

	// Messenger/email/cloud file exfiltration
	EventMessengerFile EventType = "messenger_file"   // 카톡/텔레그램/슬랙이 문서 파일 접근
	EventEmailAttach   EventType = "email_attach"      // Outlook/Thunderbird가 문서 파일 접근
	EventCloudUpload   EventType = "cloud_upload"      // 브라우저가 문서 파일 접근 (업로드 추정)

	// Other
	EventPrintJob      EventType = "print_job"
	EventScreenCapture EventType = "screen_capture"    // 스크린샷 도구 실행
	EventProcessExec   EventType = "process_exec"
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
