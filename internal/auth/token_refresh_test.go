package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/golang-jwt/jwt/v5"
)

func TestTokenRefreshMiddlewareRefreshesExpiringToken(t *testing.T) {
	jwtSvc := NewJWTService("test-secret-for-refresh")

	u := &user.User{ID: 1, Username: "testuser", Role: user.RoleAdmin}

	// Create a token that expires in 3 minutes (within 5min threshold)
	claims := &Claims{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(3 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(jwtSvc.secret)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := TokenRefreshMiddleware(jwtSvc)(inner)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tokenStr})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatal("inner handler not called")
	}

	// Should have set a new cookie
	cookies := w.Result().Cookies()
	foundNewToken := false
	for _, c := range cookies {
		if c.Name == "token" && c.Value != tokenStr {
			foundNewToken = true
		}
	}

	if !foundNewToken {
		t.Error("expected a new token cookie to be set for expiring token")
	}
}

func TestTokenRefreshMiddlewareSkipsFreshToken(t *testing.T) {
	jwtSvc := NewJWTService("test-secret-for-refresh")

	u := &user.User{ID: 1, Username: "testuser", Role: user.RoleEmployee}
	pair, _ := jwtSvc.GenerateTokenPair(u)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := TokenRefreshMiddleware(jwtSvc)(inner)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: pair.AccessToken})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should NOT set a new cookie (token is fresh, >5min remaining)
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "token" {
			t.Error("should not refresh a fresh token")
		}
	}
}

func TestTokenRefreshMiddlewareSkipsNoCookie(t *testing.T) {
	jwtSvc := NewJWTService("test-secret-for-refresh")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := TokenRefreshMiddleware(jwtSvc)(inner)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("should still call inner handler without cookie")
	}
}
