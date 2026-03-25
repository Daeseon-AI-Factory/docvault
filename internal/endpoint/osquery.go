package endpoint

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// OsqueryResult represents a single row from an osquery result log.
type OsqueryResult struct {
	Name           string            `json:"name"`
	HostIdentifier string            `json:"hostIdentifier"`
	CalendarTime   string            `json:"calendarTime"`
	UnixTime       int64             `json:"unixTime"`
	Action         string            `json:"action"`
	Columns        map[string]string `json:"columns"`
}

// OsqueryBatch represents a batch of osquery results.
type OsqueryBatch struct {
	NodeKey string          `json:"node_key"`
	Results []OsqueryResult `json:"results"`
}

// NormalizeOsqueryEvents converts osquery results into EndpointEvents.
func NormalizeOsqueryEvents(batch *OsqueryBatch, hostnameUserMap map[string]int64) []*EndpointEvent {
	events := make([]*EndpointEvent, 0, len(batch.Results))

	for _, result := range batch.Results {
		event := &EndpointEvent{
			Hostname:    result.HostIdentifier,
			EventType:   mapOsqueryAction(result.Name, result.Action, result.Columns),
			FileName:    extractFileName(result),
			FilePath:    extractFilePath(result),
			ProcessName: extractProcessName(result),
			Source:      "osquery",
			EventTime:   time.Unix(result.UnixTime, 0),
		}

		if userID, ok := hostnameUserMap[result.HostIdentifier]; ok {
			event.UserID = &userID
		}

		// Store full columns as detail
		if detail, err := json.Marshal(result.Columns); err == nil {
			event.Detail = detail
		}

		// For rename events, check if extension was changed (disguise detection)
		if result.Name == "extension_rename_detect" || result.Name == "file_events" {
			if result.Action == "MOVED" || result.Action == "RENAMED" {
				if isExtensionChanged(result.Columns) {
					event.EventType = EventExtChanged
				}
			}
		}

		events = append(events, event)
	}

	return events
}

func mapOsqueryAction(queryName, action string, columns map[string]string) EventType {
	switch queryName {
	case "file_events":
		switch action {
		case "CREATED", "UPDATED":
			return EventFileWrite
		case "DELETED":
			return EventFileDelete
		case "MOVED", "RENAMED":
			return EventFileRename
		default:
			return EventFileOpen
		}

	case "usb_devices":
		return EventUSBMount

	case "process_events":
		return EventProcessExec

	// --- Monitoring queries ---

	case "messenger_file_access":
		return EventMessengerFile

	case "email_file_access":
		return EventEmailAttach

	case "cloud_upload_access":
		return EventCloudUpload

	case "removable_drive_file_copy":
		return EventUSBCopy

	case "network_share_copy":
		return EventNetShareCopy

	case "extension_rename_detect":
		return EventFileRename // will be upgraded to EventExtChanged if extension actually changed

	case "print_jobs":
		return EventPrintJob

	case "screen_capture_detect":
		return EventScreenCapture

	default:
		return EventType(queryName + "." + action)
	}
}

// extractFileName gets the most meaningful file name from osquery columns.
func extractFileName(result OsqueryResult) string {
	// Different queries store the file path in different columns
	for _, key := range []string{"target_path", "accessed_file", "spool_file", "path"} {
		if v := result.Columns[key]; v != "" {
			return filepath.Base(v)
		}
	}
	return ""
}

// extractFilePath gets the full file path from osquery columns.
func extractFilePath(result OsqueryResult) string {
	for _, key := range []string{"target_path", "accessed_file", "spool_file", "path"} {
		if v := result.Columns[key]; v != "" {
			return v
		}
	}
	return ""
}

// extractProcessName gets the process name from osquery columns.
func extractProcessName(result OsqueryResult) string {
	if v := result.Columns["name"]; v != "" {
		return v
	}
	if v := result.Columns["process"]; v != "" {
		return v
	}
	// For process_events, extract from path
	if v := result.Columns["path"]; v != "" && result.Name == "process_events" {
		return filepath.Base(v)
	}
	return ""
}

// isExtensionChanged checks if a file rename resulted in an extension change.
// This is a key indicator of disguise attempts (e.g., secret.dwg → vacation.jpg).
func isExtensionChanged(columns map[string]string) bool {
	targetPath := columns["target_path"]
	if targetPath == "" {
		return false
	}

	// osquery file_events for MOVED may include old_path or we infer from md5 match
	// For now, we flag any rename involving suspicious extension combinations
	ext := strings.ToLower(filepath.Ext(targetPath))

	// Documents disguised as images/media
	suspiciousExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
		".tmp": true, ".dat": true, ".log": true,
	}

	// Engineering/document extensions (the real content we care about)
	docExts := map[string]bool{
		".dwg": true, ".dxf": true, ".stp": true, ".step": true,
		".igs": true, ".iges": true, ".pdf": true,
		".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true, ".csv": true, ".bom": true,
	}

	// If md5 column exists and target has suspicious ext, flag it
	// (file content hash doesn't change when just renaming)
	if columns["md5"] != "" && suspiciousExts[ext] {
		return true
	}

	// If the file was renamed and the old name had a doc extension but new doesn't
	if oldPath := columns["old_path"]; oldPath != "" {
		oldExt := strings.ToLower(filepath.Ext(oldPath))
		newExt := ext
		if docExts[oldExt] && !docExts[newExt] {
			return true // Document disguised as something else
		}
	}

	return false
}

// Messenger process names for cross-referencing
var messengerProcesses = map[string]string{
	"kakaotalk.exe": "KakaoTalk",
	"telegram.exe":  "Telegram",
	"slack.exe":     "Slack",
	"line.exe":      "LINE",
	"wechat.exe":    "WeChat",
	"discord.exe":   "Discord",
	"teams.exe":     "Microsoft Teams",
	"ms-teams.exe":  "Microsoft Teams",
}

// EmailProcesses for cross-referencing
var emailProcesses = map[string]string{
	"outlook.exe":     "Outlook",
	"thunderbird.exe": "Thunderbird",
	"mailmaster.exe":  "MailMaster",
}

// IsMessengerProcess checks if a process name belongs to a known messenger.
func IsMessengerProcess(processName string) (string, bool) {
	name, ok := messengerProcesses[strings.ToLower(processName)]
	return name, ok
}

// IsEmailProcess checks if a process name belongs to a known email client.
func IsEmailProcess(processName string) (string, bool) {
	name, ok := emailProcesses[strings.ToLower(processName)]
	return name, ok
}
