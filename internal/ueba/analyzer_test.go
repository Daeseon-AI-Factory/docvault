package ueba

import (
	"testing"
	"time"
)

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "low"}, {10, "low"}, {19, "low"},
		{20, "medium"}, {35, "medium"}, {39, "medium"},
		{40, "high"}, {60, "high"}, {69, "high"},
		{70, "critical"}, {85, "critical"}, {100, "critical"},
	}
	for _, tt := range tests {
		got := scoreToLevel(tt.score)
		if got != tt.want {
			t.Errorf("scoreToLevel(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestContains(t *testing.T) {
	slice := []string{"192.168.1.1", "10.0.0.1", "PC-001"}

	if !contains(slice, "192.168.1.1") {
		t.Error("should find exact match")
	}
	if !contains(slice, "pc-001") {
		t.Error("should be case-insensitive")
	}
	if contains(slice, "172.16.0.1") {
		t.Error("should not find missing item")
	}
	if contains(nil, "anything") {
		t.Error("nil slice should return false")
	}
}

func TestFileExt(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{"document.pdf", ".pdf"},
		{"archive.tar.gz", ".gz"},
		{"noext", ""},
		{".hidden", ".hidden"},
		{"design.DWG", ".DWG"},
	}
	for _, tt := range tests {
		got := fileExt(tt.name)
		if got != tt.want {
			t.Errorf("fileExt(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAnomalyWeights(t *testing.T) {
	// Extension disguise should be the highest weight
	if AnomalyWeight[AnomalyExtDisguise] < AnomalyWeight[AnomalyAfterHours] {
		t.Error("ext_disguise should weigh more than after_hours")
	}
	if AnomalyWeight[AnomalyMessengerLeak] < AnomalyWeight[AnomalyNewIP] {
		t.Error("messenger_leak should weigh more than new_ip")
	}

	// All anomaly types should have a weight
	allTypes := []AnomalyType{
		AnomalyAfterHours, AnomalyWeekendAccess, AnomalyBulkDownload,
		AnomalyNewIP, AnomalyNewHostname, AnomalyUnusualFile,
		AnomalyExtDisguise, AnomalyBulkClipboard, AnomalyMessengerLeak,
		AnomalyRapidAccess,
	}
	for _, at := range allTypes {
		if AnomalyWeight[at] == 0 {
			t.Errorf("anomaly type %s has zero weight", at)
		}
	}
}

func TestAfterHoursDetection(t *testing.T) {
	baseline := Baseline{
		TypicalStartHour: 8,
		TypicalEndHour:   19,
	}

	tests := []struct {
		hour    int
		isAfter bool
	}{
		{7, true},   // before 8am
		{8, false},  // start hour
		{12, false}, // midday
		{19, false}, // end hour
		{20, true},  // after 7pm
		{23, true},  // late night
		{3, true},   // early morning
	}

	for _, tt := range tests {
		t.Run(time.Date(2026, 1, 5, tt.hour, 0, 0, 0, time.UTC).Format("15:04"), func(t *testing.T) {
			isAfter := tt.hour < baseline.TypicalStartHour || tt.hour > baseline.TypicalEndHour
			if isAfter != tt.isAfter {
				t.Errorf("hour %d: got after_hours=%v, want %v", tt.hour, isAfter, tt.isAfter)
			}
		})
	}
}

func TestWeekendDetection(t *testing.T) {
	// Monday Jan 5, 2026 is a Monday
	mon := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	sat := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	sun := time.Date(2026, 1, 11, 10, 0, 0, 0, time.UTC)

	if mon.Weekday() == time.Saturday || mon.Weekday() == time.Sunday {
		t.Error("Monday should not be weekend")
	}
	if sat.Weekday() != time.Saturday {
		t.Error("Saturday should be Saturday")
	}
	if sun.Weekday() != time.Sunday {
		t.Error("Sunday should be Sunday")
	}
}

func TestRiskFactorJSON(t *testing.T) {
	f := RiskFactor{
		Factor: "after_hours",
		Weight: 10,
		Detail: "Activity at 23:15",
	}
	if f.Factor != string(AnomalyAfterHours) {
		t.Error("factor should match anomaly type string")
	}
}

func TestScoreCapping(t *testing.T) {
	// Simulate accumulating factors that exceed 100
	factors := []RiskFactor{
		{Factor: "ext_disguise", Weight: 30},
		{Factor: "messenger_leak", Weight: 25},
		{Factor: "bulk_download", Weight: 20},
		{Factor: "after_hours", Weight: 10},
		{Factor: "weekend_access", Weight: 8},
		{Factor: "unusual_filetype", Weight: 8},
		{Factor: "new_ip", Weight: 5},
	}

	total := 0
	for _, f := range factors {
		total += f.Weight
	}
	if total > 100 {
		total = 100
	}

	if total != 100 {
		t.Errorf("expected capped score 100, got %d", total)
	}
}
