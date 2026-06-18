package web

import (
	"strings"
	"testing"
)

func TestTemplateCache(t *testing.T) {
	tc, err := newTemplateCache()
	if err != nil {
		t.Fatalf("newTemplateCache: %v", err)
	}

	// Every page template must be parseable
	pages := []string{
		"login.html",
		"dashboard.html",
		"files.html",
		"file_detail.html",
		"audit_user.html",
		"audit_file.html",
		"audit_search.html",
		"admin_users.html",
		"admin_alerts.html",
		"admin_agents.html",
		"admin_install.html",
		"employee_install.html",
	}

	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			tmpl := tc.get(page)
			if tmpl == nil {
				t.Fatalf("template %s not found in cache", page)
			}

			// Verify layout pages have both "layout" and "content" templates
			if page != "login.html" && page != "employee_install.html" {
				if tmpl.Lookup("layout") == nil {
					t.Errorf("template %s missing 'layout' definition", page)
				}
				if tmpl.Lookup("content") == nil {
					t.Errorf("template %s missing 'content' definition", page)
				}
			}
		})
	}
}

func TestTemplatePagesRenderDifferentContent(t *testing.T) {
	tc, err := newTemplateCache()
	if err != nil {
		t.Fatalf("newTemplateCache: %v", err)
	}

	// Each page should render unique content when given dummy data
	type testCase struct {
		page     string
		data     map[string]interface{}
		contains string // unique string that should appear only in this page
	}

	cases := []testCase{
		{
			page: "dashboard.html",
			data: map[string]interface{}{
				"Title": "Dashboard", "Active": "dashboard", "Username": "test", "Role": "admin",
				"Stats": struct {
					TotalEvents, TodayEvents, TotalFiles int64
					ActiveAlerts                         int
				}{100, 10, 5, 2},
				"RecentLogs": []interface{}{},
				"Alerts":     []interface{}{},
			},
			contains: "Total Events",
		},
		{
			page: "admin_agents.html",
			data: map[string]interface{}{
				"Title": "Agent Status", "Active": "admin-agents", "Username": "test", "Role": "admin",
				"Agents": []interface{}{}, "PSKConfigured": true,
			},
			contains: "Endpoint Agents",
		},
		{
			page: "audit_search.html",
			data: map[string]interface{}{
				"Title": "Audit Search", "Active": "audit-search", "Username": "test", "Role": "admin",
				"Filter": struct{ UserID, Action, From, To string }{"", "", "", ""},
				"Logs":   []interface{}{},
			},
			contains: "Audit Search", // page title check is enough for differentiation
		},
	}

	rendered := make(map[string]string)
	for _, tc2 := range cases {
		t.Run(tc2.page, func(t *testing.T) {
			var buf strings.Builder
			tmpl := tc.get(tc2.page)
			err := tmpl.ExecuteTemplate(&buf, "layout", tc2.data)
			if err != nil {
				t.Fatalf("render %s: %v", tc2.page, err)
			}
			html := buf.String()

			if !strings.Contains(html, tc2.contains) {
				t.Errorf("page %s should contain %q", tc2.page, tc2.contains)
			}

			// Save for cross-check
			rendered[tc2.page] = html
		})
	}

	// Cross-check: different pages should produce different output
	if rendered["dashboard.html"] == rendered["admin_agents.html"] {
		t.Error("dashboard and admin_agents rendered identical content — template isolation is broken")
	}
}

func TestLoginTemplateRenders(t *testing.T) {
	tc, err := newTemplateCache()
	if err != nil {
		t.Fatalf("newTemplateCache: %v", err)
	}

	tmpl := tc.get("login.html")
	if tmpl == nil {
		t.Fatal("login template not found")
	}

	var buf strings.Builder
	err = tmpl.ExecuteTemplate(&buf, "login.html", map[string]interface{}{"Error": "bad password"})
	if err != nil {
		t.Fatalf("render login: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "bad password") {
		t.Error("login page should show error message")
	}
	if !strings.Contains(html, "DocVault") {
		t.Error("login page should contain DocVault branding")
	}
}

func TestLoginTemplateDemoButtonIsConditional(t *testing.T) {
	tc, err := newTemplateCache()
	if err != nil {
		t.Fatalf("newTemplateCache: %v", err)
	}

	tmpl := tc.get("login.html")
	if tmpl == nil {
		t.Fatal("login template not found")
	}

	var disabled strings.Builder
	err = tmpl.ExecuteTemplate(&disabled, "login.html", map[string]interface{}{
		"DemoLoginEnabled": false,
	})
	if err != nil {
		t.Fatalf("render disabled login: %v", err)
	}
	if strings.Contains(disabled.String(), "/login/demo") {
		t.Error("demo login action should be hidden when disabled")
	}

	var enabled strings.Builder
	err = tmpl.ExecuteTemplate(&enabled, "login.html", map[string]interface{}{
		"DemoLoginEnabled": true,
		"DefaultLang":      "en",
		"InstanceLabel":    "Portfolio Demo",
	})
	if err != nil {
		t.Fatalf("render enabled login: %v", err)
	}
	html := enabled.String()
	if !strings.Contains(html, `/login/demo`) {
		t.Error("demo login action should be rendered when enabled")
	}
	if !strings.Contains(html, "Try Demo") {
		t.Error("demo login button should render English label")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}
