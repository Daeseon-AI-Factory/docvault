package web

import (
	"net/http"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
)

// DemoReadOnly makes the demo user's session read-only. The demo user is a full
// admin (so the demo shows every screen + the AI), but this middleware blocks all
// mutations — allowing only reads (GET/HEAD) and the AI chat (which runs on a
// read-only engine) — so a public demo visitor can explore without changing or
// vandalizing anything. No-op for every non-demo user.
func DemoReadOnly(enabled bool, demoUser string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled && demoUser != "" {
				if u := auth.UserFromContext(r.Context()); u != nil && u.Username == demoUser {
					switch r.Method {
					case http.MethodGet, http.MethodHead, http.MethodOptions:
						// reads are allowed
					default:
						if r.URL.Path != "/api/agent/chat" { // AI chat allowed (read-only engine)
							http.Error(w, "데모 모드입니다 — 보기 전용이라 변경할 수 없습니다. (read-only demo)", http.StatusForbidden)
							return
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
