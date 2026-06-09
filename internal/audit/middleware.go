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

type flushStatusRecorder struct {
	*statusRecorder
}

func (sr *flushStatusRecorder) Flush() {
	sr.ResponseWriter.(http.Flusher).Flush()
}

// Middleware automatically logs every request as an audit entry.
func Middleware(repo *Repository, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if repo == nil {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			var wrapped http.ResponseWriter = rec
			if _, ok := w.(http.Flusher); ok {
				wrapped = &flushStatusRecorder{statusRecorder: rec}
			}

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
				StatusCode: rec.status,
			}

			if err := repo.Log(r.Context(), entry); err != nil && logger != nil {
				logger.Error("audit middleware: log failed", "error", err, "action", action)
			}
		})
	}
}

func deriveAction(method, path string) Action {
	switch {
	case method == "POST" && strings.HasSuffix(path, "/login"):
		return ActionLogin
	case method == "GET" && path == "/logout":
		return ActionLogout
	case method == "POST" && (path == "/api/files/upload" || path == "/files/upload"):
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
	case method == "POST" && path == "/folders/create":
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
	case method == "POST" && strings.HasPrefix(path, "/admin/users/") && strings.HasSuffix(path, "/reset-password"):
		return ActionUserResetPwd
	case method == "POST" && (path == "/api/admin/users/" || path == "/api/admin/users" || path == "/admin/users/create"):
		return ActionUserCreate
	case method == "PUT" && strings.HasPrefix(path, "/api/admin/users/"):
		return ActionUserUpdate
	case method == "POST" && strings.HasPrefix(path, "/admin/users/") && strings.HasSuffix(path, "/edit"):
		return ActionUserUpdate
	case method == "POST" && path == "/admin/alerts/rules/create":
		return ActionAlertRuleCreate
	case method == "POST" && strings.HasPrefix(path, "/admin/alerts/") && strings.HasSuffix(path, "/acknowledge"):
		return ActionAlertAck
	case method == "POST" && strings.HasPrefix(path, "/admin/monitoring/"):
		return ActionMonitoringConfigChange
	case method == "POST" && path == "/admin/tracking/add":
		return ActionTrackingAdd
	case method == "POST" && strings.HasPrefix(path, "/admin/tracking/") && strings.HasSuffix(path, "/delete"):
		return ActionTrackingDelete
	case method == "POST" && path == "/account/2fa/setup":
		return ActionTwoFactorSetup
	case method == "POST" && path == "/account/2fa/verify":
		return ActionTwoFactorVerify
	case method == "POST" && path == "/account/2fa/disable":
		return ActionTwoFactorDisable
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
	if id := rctx.URLParam("alertID"); id != "" {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			return "alert", &n
		}
	}
	if id := rctx.URLParam("id"); id != "" {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			return targetTypeFromPath(r.URL.Path), &n
		}
	}

	return "", nil
}

func targetTypeFromPath(path string) string {
	switch {
	case strings.Contains(path, "/monitoring/processes/"):
		return "monitoring_process"
	case strings.Contains(path, "/monitoring/extensions/"):
		return "monitoring_extension"
	case strings.Contains(path, "/monitoring/paths/"):
		return "monitoring_path"
	case strings.Contains(path, "/monitoring/disguise/"):
		return "monitoring_disguise_rule"
	case strings.Contains(path, "/tracking/"):
		return "tracking_rule"
	default:
		return ""
	}
}
