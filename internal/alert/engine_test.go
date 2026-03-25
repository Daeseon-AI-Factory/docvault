package alert

import (
	"encoding/json"
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
		// Comma-separated event types
		{"messenger_file,email_attach", "messenger_file", true},
		{"messenger_file,email_attach", "email_attach", true},
		{"messenger_file,email_attach", "usb_copy", false},
		{"messenger_file, email_attach", "email_attach", true}, // space tolerance
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
		// New: file extension matching
		{
			name: "file extension match",
			cond: RuleCondition{FileExtensions: []string{".dwg", ".dxf"}},
			event: endpoint.EndpointEvent{
				FileName: "blueprint.dwg",
			},
			want: true,
		},
		{
			name: "file extension no match",
			cond: RuleCondition{FileExtensions: []string{".dwg", ".dxf"}},
			event: endpoint.EndpointEvent{
				FileName: "report.pdf",
			},
			want: false,
		},
		{
			name: "file extension case insensitive",
			cond: RuleCondition{FileExtensions: []string{".DWG"}},
			event: endpoint.EndpointEvent{
				FileName: "design.dwg",
			},
			want: true,
		},
		// New: process group matching
		{
			name: "process group messenger - kakao",
			cond: RuleCondition{ProcessGroup: "messenger"},
			event: endpoint.EndpointEvent{
				ProcessName: "KakaoTalk.exe",
			},
			want: true,
		},
		{
			name: "process group messenger - telegram",
			cond: RuleCondition{ProcessGroup: "messenger"},
			event: endpoint.EndpointEvent{
				ProcessName: "Telegram.exe",
			},
			want: true,
		},
		{
			name: "process group messenger - not a messenger",
			cond: RuleCondition{ProcessGroup: "messenger"},
			event: endpoint.EndpointEvent{
				ProcessName: "explorer.exe",
			},
			want: false,
		},
		{
			name: "process group email - outlook",
			cond: RuleCondition{ProcessGroup: "email"},
			event: endpoint.EndpointEvent{
				ProcessName: "OUTLOOK.EXE",
			},
			want: true,
		},
		{
			name: "process group browser - chrome",
			cond: RuleCondition{ProcessGroup: "browser"},
			event: endpoint.EndpointEvent{
				ProcessName: "chrome.exe",
			},
			want: true,
		},
		// New: path contains
		{
			name: "path contains match",
			cond: RuleCondition{PathContains: "Engineering"},
			event: endpoint.EndpointEvent{
				FilePath: "D:\\Engineering\\designs\\part01.dwg",
			},
			want: true,
		},
		{
			name: "path contains no match",
			cond: RuleCondition{PathContains: "Engineering"},
			event: endpoint.EndpointEvent{
				FilePath: "C:\\Users\\kim\\Desktop\\photo.jpg",
			},
			want: false,
		},
		// New: min content size for clipboard
		{
			name: "min content size - above threshold",
			cond: RuleCondition{MinContentSize: 10240},
			event: endpoint.EndpointEvent{
				Detail: json.RawMessage(`{"content_size":50000}`),
			},
			want: true,
		},
		{
			name: "min content size - below threshold",
			cond: RuleCondition{MinContentSize: 10240},
			event: endpoint.EndpointEvent{
				Detail: json.RawMessage(`{"content_size":100}`),
			},
			want: false,
		},
		{
			name: "min content size - no detail",
			cond: RuleCondition{MinContentSize: 10240},
			event: endpoint.EndpointEvent{},
			want: true, // no detail means no size check applies
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

func TestMatchesProcessGroup(t *testing.T) {
	tests := []struct {
		group   string
		process string
		want    bool
	}{
		{"messenger", "KakaoTalk.exe", true},
		{"messenger", "kakaotalk.exe", true},
		{"messenger", "Telegram.exe", true},
		{"messenger", "Slack.exe", true},
		{"messenger", "Discord.exe", true},
		{"messenger", "Teams.exe", true},
		{"messenger", "LINE.exe", true},
		{"messenger", "WeChat.exe", true},
		{"messenger", "notepad.exe", false},
		{"email", "OUTLOOK.EXE", true},
		{"email", "outlook.exe", true},
		{"email", "Thunderbird.exe", true},
		{"email", "chrome.exe", false},
		{"browser", "chrome.exe", true},
		{"browser", "msedge.exe", true},
		{"browser", "firefox.exe", true},
		{"browser", "whale.exe", true},
		{"browser", "brave.exe", true},
		{"browser", "notepad.exe", false},
		{"unknown_group", "anything.exe", false},
	}

	for _, tt := range tests {
		t.Run(tt.group+"/"+tt.process, func(t *testing.T) {
			got := matchesProcessGroup(tt.group, tt.process)
			if got != tt.want {
				t.Errorf("matchesProcessGroup(%s, %s) = %v, want %v", tt.group, tt.process, got, tt.want)
			}
		})
	}
}
