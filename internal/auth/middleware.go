package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

type contextKey string

const userContextKey contextKey = "user"

type AuthUser struct {
	ID       int64
	Username string
	Role     user.Role
}

func UserFromContext(ctx context.Context) *AuthUser {
	u, _ := ctx.Value(userContextKey).(*AuthUser)
	return u
}

func Middleware(jwtSvc *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := extractToken(r)
			if tokenString == "" {
				http.Error(w, `{"error":"missing authorization token"}`, http.StatusUnauthorized)
				return
			}

			claims, err := jwtSvc.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			authUser := &AuthUser{
				ID:       claims.UserID,
				Username: claims.Username,
				Role:     claims.Role,
			}

			ctx := context.WithValue(r.Context(), userContextKey, authUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...user.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authUser := UserFromContext(r.Context())
			if authUser == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			for _, role := range roles {
				if authUser.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

// WebMiddleware is like Middleware but redirects to /login instead of returning 401.
func WebMiddleware(jwtSvc *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := extractToken(r)
			if tokenString == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			claims, err := jwtSvc.ValidateToken(tokenString)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			authUser := &AuthUser{
				ID:       claims.UserID,
				Username: claims.Username,
				Role:     claims.Role,
			}

			ctx := context.WithValue(r.Context(), userContextKey, authUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TokenRefreshMiddleware checks if the access token expires within 5 minutes
// and transparently re-issues a new cookie. This keeps web sessions alive.
func TokenRefreshMiddleware(jwtSvc *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("token")
			if err == nil && cookie.Value != "" {
				claims, err := jwtSvc.ValidateToken(cookie.Value)
				if err == nil && claims.ExpiresAt != nil {
					remaining := time.Until(claims.ExpiresAt.Time)
					if remaining > 0 && remaining < 5*time.Minute {
						// Re-issue token
						u := &user.User{
							ID:       claims.UserID,
							Username: claims.Username,
							Role:     claims.Role,
						}
						if pair, err := jwtSvc.GenerateTokenPair(u); err == nil {
							http.SetCookie(w, &http.Cookie{
								Name: "token", Value: pair.AccessToken, Path: "/",
								HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900,
							})
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractToken(r *http.Request) string {
	// Check Authorization header first
	bearer := r.Header.Get("Authorization")
	if strings.HasPrefix(bearer, "Bearer ") {
		return strings.TrimPrefix(bearer, "Bearer ")
	}
	// Fall back to cookie
	if cookie, err := r.Cookie("token"); err == nil {
		return cookie.Value
	}
	return ""
}
