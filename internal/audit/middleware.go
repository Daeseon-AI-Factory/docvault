package audit

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
)

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// Middleware automatically logs every request as an audit entry.
func Middleware(repo *Repository, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapped := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(wrapped, r)

			user := auth.UserFromContext(r.Context())
			if user == nil {
				return // unauthenticated requests don't get audit logged
			}

			action := deriveAction(r.Method, r.URL.Path)
			if action == "" {
				return // skip non-auditable routes
			}

			targetType, targetID := extractTarget(r)

			entry := Entry{
				UserID:     user.ID,
				Action:     action,
				TargetType: targetType,
				TargetID:   targetID,
				IPAddress:  r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				StatusCode: wrapped.status,
			}

			if err := repo.Log(r.Context(), entry); err != nil {
				logger.Error("audit middleware: log failed", "error", err, "action", action)
			}
		})
	}
}

func deriveAction(method, path string) Action {
	switch {
	case method == "POST" && strings.HasSuffix(path, "/login"):
		return ActionLogin
	case method == "POST" && strings.HasSuffix(path, "/upload"):
		return ActionFileUpload
	case method == "GET" && strings.Contains(path, "/download"):
		return ActionFileDownload
	case method == "DELETE" && strings.HasPrefix(path, "/api/files/"):
		return ActionFileDelete
	case method == "POST" && strings.HasSuffix(path, "/checkout"):
		return ActionFileCheckout
	case method == "POST" && strings.HasSuffix(path, "/checkin"):
		return ActionFileCheckin
	case method == "POST" && strings.HasPrefix(path, "/api/folders"):
		if strings.Contains(path, "/permissions") {
			return ActionPermissionSet
		}
		return ActionFolderCreate
	case method == "PUT" && strings.HasPrefix(path, "/api/folders/"):
		return ActionFolderUpdate
	case method == "DELETE" && strings.HasPrefix(path, "/api/folders/"):
		if strings.Contains(path, "/permissions/") {
			return ActionPermissionDel
		}
		return ActionFolderDelete
	case method == "POST" && strings.HasPrefix(path, "/api/admin/users") && strings.HasSuffix(path, "/reset-password"):
		return ActionUserResetPwd
	case method == "POST" && path == "/api/admin/users/" || method == "POST" && path == "/api/admin/users":
		return ActionUserCreate
	case method == "PUT" && strings.HasPrefix(path, "/api/admin/users/"):
		return ActionUserUpdate
	default:
		return ""
	}
}

func extractTarget(r *http.Request) (string, *int64) {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return "", nil
	}

	if id := rctx.URLParam("fileID"); id != "" {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			return "file", &n
		}
	}
	if id := rctx.URLParam("folderID"); id != "" {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			return "folder", &n
		}
	}
	if id := rctx.URLParam("userID"); id != "" {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			return "user", &n
		}
	}

	return "", nil
}
