package web

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/alert"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/audit"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/folder"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/vault"
)

type PageHandler struct {
	tc           *templateCache
	db           *pgxpool.Pool
	jwtSvc       *auth.JWTService
	vaultRepo    *vault.Repository
	folderRepo   *folder.Repository
	userRepo     *user.Repository
	auditRepo    *audit.Repository
	endpointRepo *endpoint.Repository
	alertRepo    *alert.Repository
	pskConfigured bool
	logger       *slog.Logger
}

type PageHandlerDeps struct {
	DB           *pgxpool.Pool
	JWTSvc       *auth.JWTService
	VaultRepo    *vault.Repository
	FolderRepo   *folder.Repository
	UserRepo     *user.Repository
	AuditRepo    *audit.Repository
	EndpointRepo *endpoint.Repository
	AlertRepo    *alert.Repository
	PSKConfigured bool
	Logger       *slog.Logger
}

func NewPageHandler(deps PageHandlerDeps) (*PageHandler, error) {
	tc, err := newTemplateCache()
	if err != nil {
		return nil, err
	}
	return &PageHandler{
		tc:           tc,
		db:           deps.DB,
		jwtSvc:       deps.JWTSvc,
		vaultRepo:    deps.VaultRepo,
		folderRepo:   deps.FolderRepo,
		userRepo:     deps.UserRepo,
		auditRepo:    deps.AuditRepo,
		endpointRepo: deps.EndpointRepo,
		alertRepo:    deps.AlertRepo,
		pskConfigured: deps.PSKConfigured,
		logger:       deps.Logger,
	}, nil
}

type basePage struct {
	Title    string
	Active   string
	Username string
	Role     string
	UserID   int64
}

func (h *PageHandler) base(r *http.Request, title, active string) basePage {
	u := auth.UserFromContext(r.Context())
	bp := basePage{Title: title, Active: active}
	if u != nil {
		bp.Username = u.Username
		bp.Role = string(u.Role)
		bp.UserID = u.ID
	}
	return bp
}

func (h *PageHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": ""})
}

func (h *PageHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var u user.User
	err := h.db.QueryRow(r.Context(),
		`SELECT id, username, email, password_hash, full_name, role, department, is_active, created_at, updated_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)

	if err != nil || user.CheckPassword(u.PasswordHash, password) != nil || !u.IsActive {
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "Invalid username or password"})
		return
	}

	tokens, err := h.jwtSvc.GenerateTokenPair(&u)
	if err != nil {
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "Internal error"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "token", Value: tokens.AccessToken, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token", Value: tokens.RefreshToken, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *PageHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "token", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *PageHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "Dashboard", "dashboard")

	stats, _ := h.auditRepo.GetDashboardStats(r.Context())
	if stats == nil {
		stats = &audit.DashboardStats{ActionCounts: map[string]int64{}}
	}

	recentLogs, _ := h.auditRepo.Search(r.Context(), audit.SearchParams{Limit: 10})
	alerts, _ := h.alertRepo.ListAlerts(r.Context(), true, 5, 0)

	type dashStats struct {
		TotalEvents  int64
		TodayEvents  int64
		TotalFiles   int64
		ActiveAlerts int
	}

	renderPage(w, h.tc, "dashboard.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Stats":      dashStats{stats.TotalEvents, stats.TodayEvents, 0, len(alerts)},
		"RecentLogs": recentLogs,
		"Alerts":     alerts,
	})
}

func (h *PageHandler) FileBrowser(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "Files", "files")

	var folderID *int64
	var currentFolderID int64
	if idStr := r.URL.Query().Get("folder_id"); idStr != "" {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			folderID = &id
			currentFolderID = id
		}
	}

	folders, _ := h.folderRepo.ListChildren(r.Context(), folderID)

	var files []*vault.File
	if folderID != nil {
		files, _ = h.vaultRepo.ListFilesByFolder(r.Context(), *folderID)
	}

	renderPage(w, h.tc, "files.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Folders": folders, "Files": files,
		"CurrentFolderID": currentFolderID,
		"Breadcrumbs":     []folder.Folder{},
	})
}

func (h *PageHandler) FileDetail(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "File Detail", "files")

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid file ID", http.StatusBadRequest)
		return
	}

	file, err := h.vaultRepo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	versions, _ := h.vaultRepo.ListVersions(r.Context(), fileID)
	targetType := "file"
	auditLogs, _ := h.auditRepo.Search(r.Context(), audit.SearchParams{
		TargetType: &targetType, TargetID: &fileID, Limit: 20,
	})

	u := auth.UserFromContext(r.Context())
	checkedOutByMe := file.IsCheckedOut && file.CheckedOutBy != nil && u != nil && *file.CheckedOutBy == u.ID

	renderPage(w, h.tc, "file_detail.html", map[string]interface{}{
		"Title": file.Name, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"File": file, "Versions": versions, "AuditLogs": auditLogs,
		"CheckedOutByMe": checkedOutByMe,
	})
}

func (h *PageHandler) AuditUserPage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "User Timeline", "audit-search")

	userIDStr := chi.URLParam(r, "userID")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}

	targetUser, _ := h.userRepo.GetByID(r.Context(), userID)
	if targetUser == nil {
		targetUser = &user.User{ID: userID, FullName: "Unknown"}
	}

	timeline, _ := h.endpointRepo.UnifiedTimeline(r.Context(), userID, 50, offset)

	renderPage(w, h.tc, "audit_user.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"TargetUser": targetUser, "Timeline": timeline,
		"HasMore": len(timeline) >= 50, "NextOffset": offset + 50,
	})
}

func (h *PageHandler) AuditFilePage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "File Audit", "audit-search")

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, _ := strconv.ParseInt(fileIDStr, 10, 64)

	targetType := "file"
	logs, _ := h.auditRepo.Search(r.Context(), audit.SearchParams{
		TargetType: &targetType, TargetID: &fileID, Limit: 100,
	})

	fileName := "File #" + fileIDStr
	if f, err := h.vaultRepo.GetFileByID(r.Context(), fileID); err == nil {
		fileName = f.Name
	}

	renderPage(w, h.tc, "audit_file.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"FileName": fileName, "Logs": logs,
	})
}

func (h *PageHandler) AuditSearchPage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "Audit Search", "audit-search")

	params := audit.SearchParams{Limit: 50}
	filter := struct{ UserID, Action, From, To string }{
		r.URL.Query().Get("user_id"), r.URL.Query().Get("action"),
		r.URL.Query().Get("from"), r.URL.Query().Get("to"),
	}

	if filter.UserID != "" {
		if id, err := strconv.ParseInt(filter.UserID, 10, 64); err == nil {
			params.UserID = &id
		}
	}
	if filter.Action != "" {
		a := audit.Action(filter.Action)
		params.Action = &a
	}
	if filter.From != "" {
		if t, err := time.Parse("2006-01-02T15:04", filter.From); err == nil {
			params.From = &t
		}
	}
	if filter.To != "" {
		if t, err := time.Parse("2006-01-02T15:04", filter.To); err == nil {
			params.To = &t
		}
	}

	logs, _ := h.auditRepo.Search(r.Context(), params)

	renderPage(w, h.tc, "audit_search.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Filter": filter, "Logs": logs,
	})
}

func (h *PageHandler) AdminUsersPage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "User Management", "admin-users")
	users, _ := h.userRepo.List(r.Context())

	renderPage(w, h.tc, "admin_users.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Users": users,
	})
}

func (h *PageHandler) AdminAlertsPage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "Alert Management", "admin-alerts")
	rules, _ := h.alertRepo.ListRules(r.Context(), false)
	alerts, _ := h.alertRepo.ListAlerts(r.Context(), false, 50, 0)

	renderPage(w, h.tc, "admin_alerts.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Rules": rules, "Alerts": alerts,
	})
}

func (h *PageHandler) AdminAgentsPage(w http.ResponseWriter, r *http.Request) {
	bp := h.base(r, "Agent Status", "admin-agents")

	type agentInfo struct {
		Hostname   string
		Source     string
		LastEvent  time.Time
		EventCount int64
		IsOnline   bool
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT hostname, source, MAX(event_time) as last_event, COUNT(*) as cnt
		 FROM endpoint_events WHERE event_time >= NOW() - INTERVAL '7 days'
		 GROUP BY hostname, source ORDER BY last_event DESC`)

	var agents []agentInfo
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a agentInfo
			if err := rows.Scan(&a.Hostname, &a.Source, &a.LastEvent, &a.EventCount); err == nil {
				a.IsOnline = time.Since(a.LastEvent) < 10*time.Minute
				agents = append(agents, a)
			}
		}
	}

	renderPage(w, h.tc, "admin_agents.html", map[string]interface{}{
		"Title": bp.Title, "Active": bp.Active, "Username": bp.Username, "Role": bp.Role,
		"Agents": agents, "PSKConfigured": h.pskConfigured,
	})
}
