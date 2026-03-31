package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestExportCSV(t *testing.T) {
	tid := int64(42)
	logs := []*AuditLog{
		{
			ID: 1, UserID: 10, Action: ActionFileUpload,
			TargetType: "file", TargetID: &tid, TargetName: "drawing.dwg",
			IPAddress: "192.168.1.1", UserAgent: "Mozilla/5.0", StatusCode: 200,
			CreatedAt: time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC),
		},
		{
			ID: 2, UserID: 10, Action: ActionFileDownload,
			TargetType: "file", TargetID: &tid, TargetName: "drawing.dwg",
			IPAddress: "192.168.1.1", UserAgent: "curl/7.68", StatusCode: 200,
			CreatedAt: time.Date(2026, 3, 26, 10, 5, 0, 0, time.UTC),
		},
	}

	var buf bytes.Buffer
	err := ExportCSV(&buf, logs)
	if err != nil {
		t.Fatalf("ExportCSV error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Check header
	if !strings.Contains(lines[0], "ID,Timestamp,User ID,Action") {
		t.Errorf("unexpected header: %s", lines[0])
	}

	// Check data row
	if !strings.Contains(lines[1], "drawing.dwg") {
		t.Errorf("expected drawing.dwg in row 1: %s", lines[1])
	}
	if !strings.Contains(lines[1], string(ActionFileUpload)) {
		t.Errorf("expected %s in row 1: %s", ActionFileUpload, lines[1])
	}
}

func TestExportCSVEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := ExportCSV(&buf, []*AuditLog{})
	if err != nil {
		t.Fatalf("ExportCSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 { // header only
		t.Errorf("expected 1 line (header), got %d", len(lines))
	}
}

func TestExportCSVNilTargetID(t *testing.T) {
	logs := []*AuditLog{
		{
			ID: 1, UserID: 5, Action: ActionLogin,
			TargetType: "", TargetID: nil, TargetName: "",
			IPAddress: "10.0.0.1", StatusCode: 200,
			CreatedAt: time.Now(),
		},
	}

	var buf bytes.Buffer
	err := ExportCSV(&buf, logs)
	if err != nil {
		t.Fatalf("ExportCSV error: %v", err)
	}

	if !strings.Contains(buf.String(), "login") {
		t.Error("expected login action in output")
	}
}
