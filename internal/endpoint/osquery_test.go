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
	if e.FileName != "design.dwg" {
		t.Errorf("event[0] file_name = %s, want design.dwg", e.FileName)
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
		// New monitoring queries
		{"messenger_file_access", "added", EventMessengerFile},
		{"email_file_access", "added", EventEmailAttach},
		{"cloud_upload_access", "added", EventCloudUpload},
		{"removable_drive_file_copy", "added", EventUSBCopy},
		{"network_share_copy", "added", EventNetShareCopy},
		{"print_jobs", "added", EventPrintJob},
		{"screen_capture_detect", "added", EventScreenCapture},
		{"extension_rename_detect", "added", EventFileRename},
		{"unknown_query", "something", EventType("unknown_query.something")},
	}

	for _, tt := range tests {
		t.Run(tt.query+"/"+tt.action, func(t *testing.T) {
			got := mapOsqueryAction(tt.query, tt.action, nil)
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

func TestNormalizeMessengerFileAccess(t *testing.T) {
	batch := &OsqueryBatch{
		Results: []OsqueryResult{
			{
				Name:           "messenger_file_access",
				HostIdentifier: "PC-DESIGN-001",
				UnixTime:       1700000100,
				Action:         "added",
				Columns: map[string]string{
					"name":          "KakaoTalk.exe",
					"accessed_file": "D:\\Engineering\\designs\\motor_assembly.dwg",
					"pid":           "12345",
				},
			},
		},
	}

	hostnameMap := map[string]int64{"PC-DESIGN-001": 10}
	events := NormalizeOsqueryEvents(batch, hostnameMap)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.EventType != EventMessengerFile {
		t.Errorf("type = %s, want %s", e.EventType, EventMessengerFile)
	}
	if e.ProcessName != "KakaoTalk.exe" {
		t.Errorf("process = %s, want KakaoTalk.exe", e.ProcessName)
	}
	if e.FileName != "motor_assembly.dwg" {
		t.Errorf("file_name = %s, want motor_assembly.dwg", e.FileName)
	}
	if e.FilePath != "D:\\Engineering\\designs\\motor_assembly.dwg" {
		t.Errorf("file_path = %s", e.FilePath)
	}
}

func TestNormalizeUSBCopy(t *testing.T) {
	batch := &OsqueryBatch{
		Results: []OsqueryResult{
			{
				Name:           "removable_drive_file_copy",
				HostIdentifier: "PC-ENG-003",
				UnixTime:       1700000200,
				Action:         "added",
				Columns: map[string]string{
					"target_path": "F:\\backup\\secret_specs.pdf",
					"md5":         "abc123",
				},
			},
		},
	}

	events := NormalizeOsqueryEvents(batch, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != EventUSBCopy {
		t.Errorf("type = %s, want %s", events[0].EventType, EventUSBCopy)
	}
	if events[0].FileName != "secret_specs.pdf" {
		t.Errorf("file_name = %s", events[0].FileName)
	}
}

func TestPathBaseHandlesWindowsAndPOSIXPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"windows drive path", `C:\Users\kim\Documents\design.dwg`, "design.dwg"},
		{"windows dir contains dot", `C:\Users\kim.v2\Documents\design.dwg`, "design.dwg"},
		{"windows trailing slash", `C:\Users\kim\Documents\`, "Documents"},
		{"unc path", `\\fileserver\engineering\designs\motor.step`, "motor.step"},
		{"mixed separators", `C:\Users/kim\Desktop/spec.pdf`, "spec.pdf"},
		{"posix path", `/home/kim/Documents/design.dwg`, "design.dwg"},
		{"simple filename", `design.dwg`, "design.dwg"},
		{"empty", ``, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathBase(tt.path); got != tt.want {
				t.Fatalf("pathBase(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathExtHandlesWindowsAndPOSIXPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"windows drive path", `C:\Users\kim\Documents\design.dwg`, ".dwg"},
		{"dot in directory is ignored", `C:\Users\kim.v2\Documents\README`, ""},
		{"unc path", `\\fileserver\engineering\archive.tar.gz`, ".gz"},
		{"hidden file without extension", `.env`, ""},
		{"trailing dot", `C:\Temp\filename.`, ""},
		{"posix path", `/home/kim/report.pdf`, ".pdf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathExt(tt.path); got != tt.want {
				t.Fatalf("pathExt(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractProcessNameHandlesWindowsPathsOnNonWindowsHosts(t *testing.T) {
	result := OsqueryResult{
		Name: "process_events",
		Columns: map[string]string{
			"path": `C:\Program Files\AutoCAD\acad.exe`,
		},
	}

	if got := extractProcessName(result); got != "acad.exe" {
		t.Fatalf("extractProcessName() = %q, want acad.exe", got)
	}
}

func TestExtensionChangeDetection(t *testing.T) {
	batch := &OsqueryBatch{
		Results: []OsqueryResult{
			{
				Name:           "file_events",
				HostIdentifier: "PC-ENG-001",
				UnixTime:       1700000300,
				Action:         "MOVED",
				Columns: map[string]string{
					"target_path": "C:\\Users\\kim\\Desktop\\vacation.jpg",
					"old_path":    "C:\\Users\\kim\\Desktop\\secret_design.dwg",
					"md5":         "abc123def456",
				},
			},
		},
	}

	events := NormalizeOsqueryEvents(batch, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != EventExtChanged {
		t.Errorf("type = %s, want %s (extension disguise should be detected)", events[0].EventType, EventExtChanged)
	}
}

func TestIsExtensionChanged(t *testing.T) {
	tests := []struct {
		name    string
		columns map[string]string
		want    bool
	}{
		{
			name:    "doc to image disguise",
			columns: map[string]string{"target_path": "photo.jpg", "old_path": "secret.dwg"},
			want:    true,
		},
		{
			name:    "doc to doc rename (ok)",
			columns: map[string]string{"target_path": "design_v2.dwg", "old_path": "design_v1.dwg"},
			want:    false,
		},
		{
			name:    "suspicious ext with md5",
			columns: map[string]string{"target_path": "notes.tmp", "md5": "abc123"},
			want:    true,
		},
		{
			name:    "no target path",
			columns: map[string]string{},
			want:    false,
		},
		{
			name:    "xlsx to mp3 disguise",
			columns: map[string]string{"target_path": "song.mp3", "old_path": "financials.xlsx"},
			want:    true,
		},
		{
			name:    "normal image rename",
			columns: map[string]string{"target_path": "photo2.jpg", "old_path": "photo1.jpg"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExtensionChanged(tt.columns)
			if got != tt.want {
				t.Errorf("isExtensionChanged = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsMessengerProcess(t *testing.T) {
	tests := []struct {
		process string
		want    bool
	}{
		{"kakaotalk.exe", true},
		{"KakaoTalk.exe", true},
		{"telegram.exe", true},
		{"slack.exe", true},
		{"discord.exe", true},
		{"teams.exe", true},
		{"notepad.exe", false},
		{"explorer.exe", false},
	}
	for _, tt := range tests {
		_, got := IsMessengerProcess(tt.process)
		if got != tt.want {
			t.Errorf("IsMessengerProcess(%s) = %v, want %v", tt.process, got, tt.want)
		}
	}
}

func TestIsEmailProcess(t *testing.T) {
	tests := []struct {
		process string
		want    bool
	}{
		{"outlook.exe", true},
		{"OUTLOOK.EXE", true},
		{"thunderbird.exe", true},
		{"chrome.exe", false},
	}
	for _, tt := range tests {
		_, got := IsEmailProcess(tt.process)
		if got != tt.want {
			t.Errorf("IsEmailProcess(%s) = %v, want %v", tt.process, got, tt.want)
		}
	}
}
