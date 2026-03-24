package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

func TestMiddlewareBlocksNoToken(t *testing.T) {
	svc := NewJWTService("test-secret")
	handler := Middleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareBlocksInvalidToken(t *testing.T) {
	svc := NewJWTService("test-secret")
	handler := Middleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareAllowsValidToken(t *testing.T) {
	svc := NewJWTService("test-secret")
	u := &user.User{ID: 1, Username: "testuser", Role: user.RoleEmployee}
	pair, _ := svc.GenerateTokenPair(u)

	var capturedUser *AuthUser
	handler := Middleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if capturedUser == nil {
		t.Fatal("user should be in context")
	}
	if capturedUser.ID != 1 {
		t.Errorf("user ID = %d, want 1", capturedUser.ID)
	}
	if capturedUser.Username != "testuser" {
		t.Errorf("username = %s, want testuser", capturedUser.Username)
	}
}

func TestMiddlewareReadsCookie(t *testing.T) {
	svc := NewJWTService("test-secret")
	u := &user.User{ID: 5, Username: "cookieuser", Role: user.RoleAdmin}
	pair, _ := svc.GenerateTokenPair(u)

	var capturedUser *AuthUser
	handler := Middleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: pair.AccessToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if capturedUser == nil || capturedUser.Username != "cookieuser" {
		t.Error("middleware should read JWT from cookie")
	}
}

func TestRequireRoleBlocks(t *testing.T) {
	svc := NewJWTService("test-secret")
	u := &user.User{ID: 1, Username: "employee", Role: user.RoleEmployee}
	pair, _ := svc.GenerateTokenPair(u)

	handler := Middleware(svc)(RequireRole(user.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("employee accessing admin route: status = %d, want 403", rec.Code)
	}
}

func TestRequireRoleAllows(t *testing.T) {
	svc := NewJWTService("test-secret")
	u := &user.User{ID: 1, Username: "admin", Role: user.RoleAdmin}
	pair, _ := svc.GenerateTokenPair(u)

	handler := Middleware(svc)(RequireRole(user.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("admin accessing admin route: status = %d, want 200", rec.Code)
	}
}

func TestWebMiddlewareRedirects(t *testing.T) {
	svc := NewJWTService("test-secret")
	handler := WebMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("unauthenticated web request: status = %d, want 303 redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("redirect location = %s, want /login", loc)
	}
}
