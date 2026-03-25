package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/alert"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/audit"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/folder"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/vault"
)

type RouterDeps struct {
	DB              *pgxpool.Pool
	JWTSvc          *auth.JWTService
	VaultHandler    *vault.Handler
	FolderHandler   *folder.Handler
	UserHandler     *user.Handler
	AuditRepo       *audit.Repository
	AuditHandler    *audit.Handler
	EndpointHandler *endpoint.Handler
	AlertHandler    *alert.Handler
	PageHandler     *PageHandler
	FormHandler     *FormHandler
	Logger          *slog.Logger
}

func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	authHandler := auth.NewHandler(deps.DB, deps.JWTSvc, deps.Logger)

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", staticHandler()))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Public web pages
	r.Get("/login", deps.PageHandler.LoginPage)
	r.Post("/login", deps.PageHandler.LoginSubmit)
	r.Get("/logout", deps.PageHandler.Logout)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})

	// Public API routes
	r.Post("/api/auth/login", authHandler.Login)
	r.Post("/api/auth/refresh", authHandler.Refresh)

	// Agent event receivers (PSK-authenticated, not JWT)
	r.Post("/api/events/osquery", deps.EndpointHandler.ReceiveOsquery)
	r.Post("/api/events/clipboard", deps.EndpointHandler.ReceiveClipboard)
	r.Post("/api/enroll", deps.EndpointHandler.Enroll)
	r.Post("/api/config", deps.EndpointHandler.AgentConfig)

	// Protected API routes
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(deps.JWTSvc))
		r.Use(audit.Middleware(deps.AuditRepo, deps.Logger))

		r.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
			u := auth.UserFromContext(r.Context())
			if u == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       u.ID,
				"username": u.Username,
				"role":     u.Role,
			})
		})

		// File vault routes
		r.Post("/api/files/upload", deps.VaultHandler.Upload)
		r.Get("/api/files", deps.VaultHandler.ListFiles)
		r.Get("/api/files/{fileID}", deps.VaultHandler.GetFile)
		r.Get("/api/files/{fileID}/download", deps.VaultHandler.Download)
		r.Delete("/api/files/{fileID}", deps.VaultHandler.DeleteFile)
		r.Post("/api/files/{fileID}/checkout", deps.VaultHandler.Checkout)
		r.Post("/api/files/{fileID}/checkin", deps.VaultHandler.Checkin)

		// Folder routes
		r.Post("/api/folders", deps.FolderHandler.Create)
		r.Get("/api/folders", deps.FolderHandler.List)
		r.Get("/api/folders/{folderID}", deps.FolderHandler.Get)
		r.Put("/api/folders/{folderID}", deps.FolderHandler.Update)
		r.Delete("/api/folders/{folderID}", deps.FolderHandler.Delete)
		r.Post("/api/folders/{folderID}/permissions", deps.FolderHandler.SetPermission)
		r.Get("/api/folders/{folderID}/permissions", deps.FolderHandler.ListPermissions)
		r.Delete("/api/folders/{folderID}/permissions/{userID}", deps.FolderHandler.RemovePermission)

		// Admin user management routes
		r.Route("/api/admin/users", func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Post("/", deps.UserHandler.Create)
			r.Get("/", deps.UserHandler.List)
			r.Get("/{userID}", deps.UserHandler.Get)
			r.Put("/{userID}", deps.UserHandler.Update)
			r.Post("/{userID}/reset-password", deps.UserHandler.ResetPassword)
		})

		// Audit routes
		r.Get("/api/audit/users/{userID}", deps.AuditHandler.UserTimeline)
		r.Get("/api/audit/files/{fileID}", deps.AuditHandler.FileTimeline)
		r.Get("/api/audit/search", deps.AuditHandler.Search)
		r.Get("/api/audit/dashboard", deps.AuditHandler.Dashboard)

		// Endpoint event routes
		r.Get("/api/events/search", deps.EndpointHandler.SearchEvents)
		r.Get("/api/timeline/{userID}", deps.EndpointHandler.UnifiedTimeline)

		// Alert routes
		r.Get("/api/alerts", deps.AlertHandler.ListAlerts)
		r.Post("/api/alerts/{alertID}/acknowledge", deps.AlertHandler.Acknowledge)
		r.Get("/api/alerts/rules", deps.AlertHandler.ListRules)
		r.Post("/api/alerts/rules", deps.AlertHandler.CreateRule)
	})

	// Protected web pages (cookie-based auth + auto-refresh + CSRF)
	r.Group(func(r chi.Router) {
		r.Use(auth.TokenRefreshMiddleware(deps.JWTSvc))
		r.Use(auth.WebMiddleware(deps.JWTSvc))
		r.Use(CSRFMiddleware(deps.JWTSvc.Secret()))

		r.Get("/dashboard", deps.PageHandler.Dashboard)
		r.Get("/files", deps.PageHandler.FileBrowser)
		r.Get("/files/{fileID}", deps.PageHandler.FileDetail)

		r.Get("/audit/users/{userID}", deps.PageHandler.AuditUserPage)
		r.Get("/audit/files/{fileID}", deps.PageHandler.AuditFilePage)
		r.Get("/audit/search", deps.PageHandler.AuditSearchPage)

		r.Get("/events/search", deps.PageHandler.EventsSearchPage)
		r.Get("/api/events/export", deps.PageHandler.ExportEventsCSV)
		r.Get("/api/audit/export", deps.AuditHandler.ExportCSV)
		r.Get("/api/audit/verify", deps.AuditHandler.VerifyIntegrity)

		r.Get("/admin/users", deps.PageHandler.AdminUsersPage)
		r.Get("/admin/alerts", deps.PageHandler.AdminAlertsPage)
		r.Get("/admin/agents", deps.PageHandler.AdminAgentsPage)

		// Form POST handlers (accept form data, redirect)
		r.Post("/files/upload", deps.FormHandler.UploadFile)
		r.Post("/files/{fileID}/checkout", deps.FormHandler.CheckoutFile)
		r.Post("/files/{fileID}/checkin", deps.FormHandler.CheckinFile)
		r.Post("/folders/create", deps.FormHandler.CreateFolder)
		r.Post("/admin/users/create", deps.FormHandler.CreateUser)
		r.Post("/admin/alerts/rules/create", deps.FormHandler.CreateAlertRule)
		r.Post("/admin/alerts/{alertID}/acknowledge", deps.FormHandler.AcknowledgeAlert)
		r.Get("/admin/users/{userID}/edit", deps.PageHandler.AdminUserEditPage)
		r.Post("/admin/users/{userID}/edit", deps.FormHandler.EditUser)
		r.Post("/admin/users/{userID}/reset-password", deps.FormHandler.ResetPassword)
	})

	return r
}
