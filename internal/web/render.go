package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var funcMap = template.FuncMap{
	"formatBytes": formatBytes,
	"printf":      fmt.Sprintf,
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// templateCache holds per-page parsed templates (layout + page).
// Each page template is parsed separately to avoid {{define}} conflicts.
type templateCache struct {
	mu    sync.RWMutex
	cache map[string]*template.Template
}

func newTemplateCache() (*templateCache, error) {
	tc := &templateCache{cache: make(map[string]*template.Template)}

	// Pages that use the layout wrapper
	layoutPages := []string{
		"dashboard.html",
		"files.html",
		"file_detail.html",
		"audit_user.html",
		"audit_file.html",
		"audit_search.html",
		"admin_users.html",
		"admin_user_edit.html",
		"admin_alerts.html",
		"admin_agents.html",
		"admin_install.html",
		"admin_monitoring.html",
		"events_search.html",
		"totp_setup.html",
		"admin_tracking.html",
	}

	for _, page := range layoutPages {
		t, err := template.New("").Funcs(funcMap).ParseFS(templateFS,
			"templates/layout.html",
			"templates/"+page,
		)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		tc.cache[page] = t
	}

	// Standalone pages (no layout)
	loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}
	tc.cache["login.html"] = loginTmpl

	login2faTmpl, err := template.New("login_2fa.html").Funcs(funcMap).ParseFS(templateFS, "templates/login_2fa.html")
	if err != nil {
		return nil, fmt.Errorf("parse login_2fa template: %w", err)
	}
	tc.cache["login_2fa.html"] = login2faTmpl

	return tc, nil
}

func (tc *templateCache) get(name string) *template.Template {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.cache[name]
}

// renderPage renders a layout-based page template.
func renderPage(w http.ResponseWriter, tc *templateCache, page string, data interface{}) {
	t := tc.get(page)
	if t == nil {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("render template", "page", page, "error", err)
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

// renderStandalone renders a standalone template (no layout).
func renderStandalone(w http.ResponseWriter, tc *templateCache, page string, data interface{}) {
	t := tc.get(page)
	if t == nil {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, page, data); err != nil {
		slog.Error("render template", "page", page, "error", err)
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.FileServer(http.FS(sub))
}

func downloadHandler() http.Handler {
	agentFiles := http.FileServer(http.Dir("/vault/agents"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch name {
		case "install-windows.ko.html", "manual.ko.html":
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFileFS(w, r, staticFS, "static/"+name)
		default:
			agentFiles.ServeHTTP(w, r)
		}
	})
}
