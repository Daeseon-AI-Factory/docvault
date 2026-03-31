package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFMiddlewareBlocksWithoutToken(t *testing.T) {
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// POST without CSRF token should be blocked
	req := httptest.NewRequest("POST", "/test", strings.NewReader("data=value"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Set a cookie so middleware has something to compare against
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "valid-token"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", w.Code)
	}
}

func TestCSRFMiddlewareAllowsGET(t *testing.T) {
	called := false
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("GET request should pass through CSRF middleware")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCSRFMiddlewareAllowsMatchingToken(t *testing.T) {
	called := false
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	token := generateCSRFToken("test-secret")

	req := httptest.NewRequest("POST", "/test", strings.NewReader("csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("POST with valid CSRF token should pass through")
	}
}

func TestCSRFMiddlewareBlocksMismatchedToken(t *testing.T) {
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/test", strings.NewReader("csrf_token=wrong-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "correct-token"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched token, got %d", w.Code)
	}
}

func TestCSRFMiddlewareAcceptsHeader(t *testing.T) {
	called := false
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	token := generateCSRFToken("test-secret")

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("POST with CSRF header should pass through")
	}
}

func TestCSRFMiddlewareIssuesCookie(t *testing.T) {
	handler := CSRFMiddleware("test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			found = true
			if c.Value == "" {
				t.Error("CSRF cookie should not be empty")
			}
		}
	}
	if !found {
		t.Error("CSRF cookie should be set on first request")
	}
}

func TestCSRFTokenExtraction(t *testing.T) {
	// Without cookie
	req := httptest.NewRequest("GET", "/", nil)
	if CSRFToken(req) != "" {
		t.Error("should return empty string when no cookie")
	}

	// With cookie
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "my-token"})
	if CSRFToken(req) != "my-token" {
		t.Errorf("expected my-token, got %s", CSRFToken(req))
	}
}

func TestGenerateCSRFToken(t *testing.T) {
	t1 := generateCSRFToken("secret1")
	t2 := generateCSRFToken("secret1")

	if t1 == t2 {
		t.Error("tokens should be unique (random component)")
	}

	// Token format: payload.timestamp.signature
	parts := strings.Split(t1, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts (payload.timestamp.sig), got %d", len(parts))
	}
}
