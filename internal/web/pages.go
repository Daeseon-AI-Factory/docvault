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

// pageData builds a template data map with base fields + CSRF token pre-filled.
func (h *PageHandler) pageData(r *http.Request, title, active string) map[string]interface{} {
	bp := h.base(r, title, active)
	return map[string]interface{}{
		"Title":     bp.Title,
		"Active":    bp.Active,
		"Username":  bp.Username,
		"Role":      bp.Role,
		"UserID":    bp.UserID,
		"CSRFToken": CSRFToken(r),
	}
}

func (h *PageHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "", "CSRFToken": CSRFToken(r)})
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
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "Invalid username or password", "CSRFToken": CSRFToken(r)})
		return
	}

	tokens, err := h.jwtSvc.GenerateTokenPair(&u)
	if err != nil {
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "Internal error", "CSRFToken": CSRFToken(r)})
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

	// Query suspicious events from last 24h
	suspiciousTypes := []endpoint.EventType{
		endpoint.EventMessengerFile, endpoint.EventEmailAttach, endpoint.EventExtChanged,
		endpoint.EventUSBCopy, endpoint.EventCloudUpload, endpoint.EventScreenCapture,
		endpoint.EventNetShareCopy,
	}
	var suspiciousEvents []*endpoint.EndpointEvent
	for _, et := range suspiciousTypes {
		evts, _ := h.endpointRepo.SearchByType(r.Context(), et, 10)
		suspiciousEvents = append(suspiciousEvents, evts...)
	}

	data := h.pageData(r, "Dashboard", "dashboard")
	data["Stats"] = dashStats{stats.TotalEvents, stats.TodayEvents, 0, len(alerts)}
	data["RecentLogs"] = recentLogs
	data["Alerts"] = alerts
	data["SuspiciousEvents"] = suspiciousEvents
	renderPage(w, h.tc, "dashboard.html", data)
}

func (h *PageHandler) FileBrowser(w http.ResponseWriter, r *http.Request) {
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

	// Build breadcrumb chain
	breadcrumbs := h.buildBreadcrumbs(r, folderID)

	data := h.pageData(r, "Files", "files")
	data["Folders"] = folders
	data["Files"] = files
	data["CurrentFolderID"] = currentFolderID
	data["Breadcrumbs"] = breadcrumbs
	renderPage(w, h.tc, "files.html", data)
}

func (h *PageHandler) FileDetail(w http.ResponseWriter, r *http.Request) {
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

	data := h.pageData(r, file.Name, "files")
	data["File"] = file
	data["Versions"] = versions
	data["AuditLogs"] = auditLogs
	data["CheckedOutByMe"] = checkedOutByMe
	renderPage(w, h.tc, "file_detail.html", data)
}

func (h *PageHandler) AuditUserPage(w http.ResponseWriter, r *http.Request) {
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

	data := h.pageData(r, "User Timeline", "audit-search")
	data["TargetUser"] = targetUser
	data["Timeline"] = timeline
	data["HasMore"] = len(timeline) >= 50
	data["NextOffset"] = offset + 50
	renderPage(w, h.tc, "audit_user.html", data)
}

func (h *PageHandler) AuditFilePage(w http.ResponseWriter, r *http.Request) {
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

	data := h.pageData(r, "File Audit", "audit-search")
	data["FileName"] = fileName
	data["Logs"] = logs
	renderPage(w, h.tc, "audit_file.html", data)
}

func (h *PageHandler) AuditSearchPage(w http.ResponseWriter, r *http.Request) {
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

	data := h.pageData(r, "Audit Search", "audit-search")
	data["Filter"] = filter
	data["Logs"] = logs
	renderPage(w, h.tc, "audit_search.html", data)
}

func (h *PageHandler) AdminUsersPage(w http.ResponseWriter, r *http.Request) {
	users, _ := h.userRepo.List(r.Context())
	data := h.pageData(r, "User Management", "admin-users")
	data["Users"] = users
	renderPage(w, h.tc, "admin_users.html", data)
}

func (h *PageHandler) AdminUserEditPage(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "userID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	u, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	data := h.pageData(r, "Edit User", "admin-users")
	data["EditUser"] = u
	renderPage(w, h.tc, "admin_user_edit.html", data)
}

func (h *PageHandler) AdminAlertsPage(w http.ResponseWriter, r *http.Request) {
	rules, _ := h.alertRepo.ListRules(r.Context(), false)
	alerts, _ := h.alertRepo.ListAlerts(r.Context(), false, 50, 0)

	data := h.pageData(r, "Alert Management", "admin-alerts")
	data["Rules"] = rules
	data["Alerts"] = alerts
	renderPage(w, h.tc, "admin_alerts.html", data)
}

func (h *PageHandler) AdminAgentsPage(w http.ResponseWriter, r *http.Request) {
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

	data := h.pageData(r, "Agent Status", "admin-agents")
	data["Agents"] = agents
	data["PSKConfigured"] = h.pskConfigured
	renderPage(w, h.tc, "admin_agents.html", data)
}

// buildBreadcrumbs walks up the folder tree to build navigation breadcrumbs.
func (h *PageHandler) buildBreadcrumbs(r *http.Request, folderID *int64) []folder.Folder {
	if folderID == nil {
		return nil
	}
	var crumbs []folder.Folder
	currentID := folderID
	for currentID != nil {
		f, err := h.folderRepo.GetByID(r.Context(), *currentID)
		if err != nil {
			break
		}
		crumbs = append([]folder.Folder{*f}, crumbs...)
		currentID = f.ParentID
	}
	return crumbs
}
