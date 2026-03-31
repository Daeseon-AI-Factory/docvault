package endpoint

import (
	"testing"
)

// mockDisguiseChecker simulates the DB-based monitoring config
type mockDisguiseChecker struct {
	categories map[string]string // ext -> category
	disguises  map[string]bool   // "category|ext" -> true
}

func (m *mockDisguiseChecker) IsDisguise(oldExt, newExt string) bool {
	cat := m.categories[oldExt]
	if cat == "" {
		return false
	}
	return m.disguises[cat+"|"+newExt]
}

func (m *mockDisguiseChecker) GetExtensionCategory(ext string) string {
	return m.categories[ext]
}

func TestIsExtensionChangedWithChecker(t *testing.T) {
	checker := &mockDisguiseChecker{
		categories: map[string]string{
			".dwg":  "cad",
			".pdf":  "document",
			".xlsx": "spreadsheet",
		},
		disguises: map[string]bool{
			"cad|.jpg":         true,
			"cad|.mp3":         true,
			"document|.jpg":    true,
			"spreadsheet|.tmp": true,
		},
	}

	tests := []struct {
		name    string
		columns map[string]string
		want    bool
	}{
		{
			name: "CAD to JPG disguise detected via checker",
			columns: map[string]string{
				"target_path": `C:\temp\design.jpg`,
				"old_path":    `C:\temp\design.dwg`,
			},
			want: true,
		},
		{
			name: "CAD to MP3 disguise detected",
			columns: map[string]string{
				"target_path": `C:\temp\model.mp3`,
				"old_path":    `C:\temp\model.dwg`,
			},
			want: true,
		},
		{
			name: "PDF to JPG disguise detected",
			columns: map[string]string{
				"target_path": `C:\temp\report.jpg`,
				"old_path":    `C:\temp\report.pdf`,
			},
			want: true,
		},
		{
			name: "same extension, not a disguise",
			columns: map[string]string{
				"target_path": `C:\temp\file.dwg`,
				"old_path":    `C:\temp\old.dwg`,
			},
			want: false,
		},
		{
			name: "unknown extension, not a disguise",
			columns: map[string]string{
				"target_path": `C:\temp\photo.png`,
				"old_path":    `C:\temp\photo.bmp`,
			},
			want: false,
		},
		{
			name: "XLSX to TMP disguise",
			columns: map[string]string{
				"target_path": `C:\temp\data.tmp`,
				"old_path":    `C:\temp\data.xlsx`,
			},
			want: true,
		},
		{
			name: "no target_path",
			columns: map[string]string{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExtensionChangedWithChecker(tt.columns, checker)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsExtensionChangedFallbackWithoutChecker(t *testing.T) {
	tests := []struct {
		name    string
		columns map[string]string
		want    bool
	}{
		{
			name: "fallback: dwg to jpg",
			columns: map[string]string{
				"target_path": `C:\docs\blueprint.jpg`,
				"old_path":    `C:\docs\blueprint.dwg`,
			},
			want: true,
		},
		{
			name: "fallback: doc to doc (safe)",
			columns: map[string]string{
				"target_path": `C:\docs\report.docx`,
				"old_path":    `C:\docs\report.doc`,
			},
			want: false,
		},
		{
			name: "fallback: suspicious ext with md5",
			columns: map[string]string{
				"target_path": `C:\docs\secret.tmp`,
				"md5":         "abc123",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// nil checker = fallback to hardcoded
			got := isExtensionChangedWithChecker(tt.columns, nil)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeOsqueryEventsWithDisguiseChecker(t *testing.T) {
	checker := &mockDisguiseChecker{
		categories: map[string]string{".dwg": "cad"},
		disguises:  map[string]bool{"cad|.jpg": true},
	}

	batch := &OsqueryBatch{
		NodeKey: "test-key",
		Results: []OsqueryResult{
			{
				Name:           "extension_rename_detect",
				HostIdentifier: "PC-001",
				UnixTime:       1711411200,
				Action:         "MOVED",
				Columns: map[string]string{
					"target_path": `C:\temp\plan.jpg`,
					"old_path":    `C:\temp\plan.dwg`,
				},
			},
		},
	}

	events := NormalizeOsqueryEventsWithChecker(batch, map[string]int64{"PC-001": 42}, checker)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].EventType != EventExtChanged {
		t.Errorf("expected event type %s, got %s", EventExtChanged, events[0].EventType)
	}

	if events[0].UserID == nil || *events[0].UserID != 42 {
		t.Error("expected user ID 42 from hostname map")
	}
}
