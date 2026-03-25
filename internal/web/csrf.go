package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

const (
	csrfCookieName = "csrf_token"
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfMaxAge     = 3600 // 1 hour
)

// CSRFMiddleware protects POST/PUT/DELETE requests against cross-site request forgery.
// GET/HEAD/OPTIONS are safe methods and are not checked.
func CSRFMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Issue token cookie if missing
			cookie, err := r.Cookie(csrfCookieName)
			if err != nil || cookie.Value == "" {
				token := generateCSRFToken(secret)
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: false, // JS needs to read it for AJAX
					SameSite: http.SameSiteStrictMode,
					MaxAge:   csrfMaxAge,
				})
				cookie = &http.Cookie{Value: token}
			}

			// Safe methods don't need validation
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate token from form field or header
			submitted := r.FormValue(csrfFieldName)
			if submitted == "" {
				submitted = r.Header.Get(csrfHeaderName)
			}

			if !validateCSRFToken(secret, cookie.Value, submitted) {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func generateCSRFToken(secret string) string {
	random := make([]byte, 32)
	rand.Read(random)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload := base64.RawURLEncoding.EncodeToString(random) + "." + timestamp

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payload + "." + sig
}

func validateCSRFToken(secret, cookieToken, submittedToken string) bool {
	if cookieToken == "" || submittedToken == "" {
		return false
	}
	return cookieToken == submittedToken
}

// CSRFToken extracts the current CSRF token from the request cookie.
// Used by page handlers to inject into template data.
func CSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
