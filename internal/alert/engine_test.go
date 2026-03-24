package alert

import (
	"testing"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
)

func TestMatchesEventType(t *testing.T) {
	tests := []struct {
		ruleType  string
		eventType string
		want      bool
	}{
		{"*", "usb_copy", true},
		{"*", "file_delete", true},
		{"usb_copy", "usb_copy", true},
		{"USB_COPY", "usb_copy", true}, // case insensitive
		{"usb_copy", "file_delete", false},
		{"clipboard_copy", "clipboard_paste", false},
	}

	for _, tt := range tests {
		t.Run(tt.ruleType+"_vs_"+tt.eventType, func(t *testing.T) {
			got := matchesEventType(tt.ruleType, tt.eventType)
			if got != tt.want {
				t.Errorf("matchesEventType(%s, %s) = %v, want %v", tt.ruleType, tt.eventType, got, tt.want)
			}
		})
	}
}

func TestMatchesCondition(t *testing.T) {
	tests := []struct {
		name  string
		cond  RuleCondition
		event endpoint.EndpointEvent
		want  bool
	}{
		{
			name: "empty condition matches everything",
			cond: RuleCondition{},
			event: endpoint.EndpointEvent{
				FileName:    "secret.dwg",
				ProcessName: "explorer.exe",
			},
			want: true,
		},
		{
			name: "file name contains match",
			cond: RuleCondition{FileNameContains: ".dwg"},
			event: endpoint.EndpointEvent{
				FileName: "important_design.dwg",
			},
			want: true,
		},
		{
			name: "file name contains no match",
			cond: RuleCondition{FileNameContains: ".pdf"},
			event: endpoint.EndpointEvent{
				FileName: "important_design.dwg",
			},
			want: false,
		},
		{
			name: "file name case insensitive",
			cond: RuleCondition{FileNameContains: ".DWG"},
			event: endpoint.EndpointEvent{
				FileName: "design.dwg",
			},
			want: true,
		},
		{
			name: "process name match",
			cond: RuleCondition{ProcessName: "cmd.exe"},
			event: endpoint.EndpointEvent{
				ProcessName: "cmd.exe",
			},
			want: true,
		},
		{
			name: "process name no match",
			cond: RuleCondition{ProcessName: "cmd.exe"},
			event: endpoint.EndpointEvent{
				ProcessName: "explorer.exe",
			},
			want: false,
		},
		{
			name: "combined: both must match",
			cond: RuleCondition{
				FileNameContains: "secret",
				ProcessName:      "cmd.exe",
			},
			event: endpoint.EndpointEvent{
				FileName:    "secret_plan.pdf",
				ProcessName: "cmd.exe",
			},
			want: true,
		},
		{
			name: "combined: file matches but process doesn't",
			cond: RuleCondition{
				FileNameContains: "secret",
				ProcessName:      "cmd.exe",
			},
			event: endpoint.EndpointEvent{
				FileName:    "secret_plan.pdf",
				ProcessName: "explorer.exe",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesCondition(&tt.cond, &tt.event)
			if got != tt.want {
				t.Errorf("matchesCondition = %v, want %v", got, tt.want)
			}
		})
	}
}
