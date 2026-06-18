package web

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/alert"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/audit"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/folder"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/monitoring"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/vault"
)

// UEBARiskProvider returns top risky users for the dashboard widget.
type UEBARiskProvider interface {
	GetTopRiskUsers(ctx context.Context, limit int) ([]UserRiskSummary, error)
}

// FileTrackerUI provides tracked file data for admin pages.
type FileTrackerUI interface {
	List(ctx context.Context) ([]TrackedFileView, error)
	GetAllDetections(ctx context.Context, limit int) ([]DetectionView, error)
	GetDetections(ctx context.Context, trackedFileID int64, limit int) ([]DetectionView, error)
	Register(ctx context.Context, name, sha256, md5, sensitivity, description string, userID int64) error
	Unregister(ctx context.Context, id int64) error
}

type TrackedFileView struct {
	ID           int64  `json:"id"`
	OriginalName string `json:"original_name"`
	SHA256Hash   string `json:"sha256_hash"`
	Sensitivity  string `json:"sensitivity"`
	Description  string `json:"description"`
	IsActive     bool   `json:"is_active"`
}

type DetectionView struct {
	ID            int64     `json:"id"`
	TrackedFileID int64     `json:"tracked_file_id"`
	OriginalName  string    `json:"original_name"`
	Sensitivity   string    `json:"sensitivity"`
	FoundName     string    `json:"found_name"`
	FoundPath     string    `json:"found_path"`
	Hostname      string    `json:"hostname"`
	EventType     string    `json:"event_type"`
	ProcessName   string    `json:"process_name"`
	DetectedAt    time.Time `json:"detected_at"`
}

// UserRiskSummary is a dashboard-facing risk summary.
type UserRiskSummary struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Score    int    `json:"score"`
	Level    string `json:"level"`
}

type PageHandler struct {
	tc             *templateCache
	db             *pgxpool.Pool
	jwtSvc         *auth.JWTService
	vaultRepo      *vault.Repository
	folderRepo     *folder.Repository
	userRepo       *user.Repository
	auditRepo      *audit.Repository
	endpointRepo   *endpoint.Repository
	alertRepo      *alert.Repository
	monitorHandler *monitoring.Handler
	uebaProvider   UEBARiskProvider
	fileTracker    FileTrackerUI
	pskConfigured  bool
	agentPSK       string
	totpProtector  *auth.SecretProtector
	rateLimiter    *LoginRateLimiter
	logger         *slog.Logger
}

type PageHandlerDeps struct {
	DB             *pgxpool.Pool
	JWTSvc         *auth.JWTService
	VaultRepo      *vault.Repository
	FolderRepo     *folder.Repository
	UserRepo       *user.Repository
	AuditRepo      *audit.Repository
	EndpointRepo   *endpoint.Repository
	AlertRepo      *alert.Repository
	MonitorHandler *monitoring.Handler
	UEBAAnalyzer   UEBARiskProvider
	FileTracker    FileTrackerUI
	PSKConfigured  bool
	AgentPSK       string
	TOTPProtector  *auth.SecretProtector
	Logger         *slog.Logger
}

func NewPageHandler(deps PageHandlerDeps) (*PageHandler, error) {
	tc, err := newTemplateCache()
	if err != nil {
		return nil, err
	}
	return &PageHandler{
		tc:             tc,
		db:             deps.DB,
		jwtSvc:         deps.JWTSvc,
		vaultRepo:      deps.VaultRepo,
		folderRepo:     deps.FolderRepo,
		userRepo:       deps.UserRepo,
		auditRepo:      deps.AuditRepo,
		endpointRepo:   deps.EndpointRepo,
		alertRepo:      deps.AlertRepo,
		monitorHandler: deps.MonitorHandler,
		uebaProvider:   deps.UEBAAnalyzer,
		fileTracker:    deps.FileTracker,
		pskConfigured:  deps.PSKConfigured,
		agentPSK:       deps.AgentPSK,
		totpProtector:  deps.TOTPProtector,
		rateLimiter:    NewLoginRateLimiter(5, 10*time.Minute, 15*time.Minute),
		logger:         deps.Logger,
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

func (h *PageHandler) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.AuthUser, bool) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	if u.Role != user.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return u, true
}

func (h *PageHandler) hasFolderAccess(r *http.Request, u *auth.AuthUser, folderID int64, required folder.Permission) (bool, error) {
	if u == nil {
		return false, nil
	}
	if u.Role == user.RoleAdmin {
		return true, nil
	}
	if h.folderRepo == nil {
		return false, nil
	}
	return h.folderRepo.CheckAccess(r.Context(), folderID, u.ID, required)
}

func (h *PageHandler) requireFolderAccess(w http.ResponseWriter, r *http.Request, u *auth.AuthUser, folderID int64, required folder.Permission) bool {
	allowed, err := h.hasFolderAccess(r, u, folderID, required)
	if err != nil {
		h.logger.Error("page: check folder access", "error", err, "folder_id", folderID, "user_id", u.ID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (h *PageHandler) filterReadableFolders(r *http.Request, u *auth.AuthUser, folders []*folder.Folder) ([]*folder.Folder, error) {
	if u == nil || u.Role == user.RoleAdmin {
		return folders, nil
	}
	filtered := folders[:0]
	for _, f := range folders {
		allowed, err := h.hasFolderAccess(r, u, f.ID, folder.PermRead)
		if err != nil {
			return nil, err
		}
		if allowed {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

func (h *PageHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": "", "CSRFToken": CSRFToken(r)})
}

func (h *PageHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := ExtractIP(r)

	// Rate limit check
	if h.rateLimiter.IsLocked(ip) {
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{
			"Error": "Too many failed attempts. Please try again in 15 minutes.", "CSRFToken": CSRFToken(r),
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var u user.User
	err := h.db.QueryRow(r.Context(),
		`SELECT id, username, email, password_hash, full_name, role, department, is_active,
		        COALESCE(totp_secret,''), COALESCE(totp_enabled,false), created_at, updated_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive,
		&u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		locked := h.rateLimiter.RecordFailure(ip)
		remaining := h.rateLimiter.RemainingAttempts(ip)
		errMsg := fmt.Sprintf("Invalid username or password (%d attempts remaining)", remaining)
		if locked {
			errMsg = "Account locked for 15 minutes due to too many failed attempts"
		}
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": errMsg, "CSRFToken": CSRFToken(r)})
		return
	}
	if !u.IsActive {
		h.logAudit(r, u.ID, audit.ActionLogin, http.StatusForbidden)
		locked := h.rateLimiter.RecordFailure(ip)
		remaining := h.rateLimiter.RemainingAttempts(ip)
		errMsg := fmt.Sprintf("Invalid username or password (%d attempts remaining)", remaining)
		if locked {
			errMsg = "Account locked for 15 minutes due to too many failed attempts"
		}
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": errMsg, "CSRFToken": CSRFToken(r)})
		return
	}
	if user.CheckPassword(u.PasswordHash, password) != nil {
		h.logAudit(r, u.ID, audit.ActionLogin, http.StatusUnauthorized)
		locked := h.rateLimiter.RecordFailure(ip)
		remaining := h.rateLimiter.RemainingAttempts(ip)
		errMsg := fmt.Sprintf("Invalid username or password (%d attempts remaining)", remaining)
		if locked {
			errMsg = "Account locked for 15 minutes due to too many failed attempts"
		}
		renderStandalone(w, h.tc, "login.html", map[string]interface{}{"Error": errMsg, "CSRFToken": CSRFToken(r)})
		return
	}

	// If 2FA is enabled, redirect to TOTP verification page instead of logging in
	if u.TOTPEnabled {
		// Store user ID in a short-lived pending-2fa cookie (HMAC signed)
		pendingToken, _ := h.jwtSvc.GeneratePending2FAToken(u.ID)
		http.SetCookie(w, &http.Cookie{
			Name: "pending_2fa", Value: pendingToken, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 300, // 5 minutes
		})
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}

	// Success: clear rate limiter
	h.rateLimiter.RecordSuccess(ip)
	h.issueSessionCookies(w, &u)
	h.logAudit(r, u.ID, audit.ActionLogin, http.StatusSeeOther)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// issueSessionCookies sets the JWT access + refresh cookies.
func (h *PageHandler) issueSessionCookies(w http.ResponseWriter, u *user.User) {
	tokens, err := h.jwtSvc.GenerateTokenPair(u)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "token", Value: tokens.AccessToken, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 900,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token", Value: tokens.RefreshToken, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400,
	})
}

func (h *PageHandler) sealTOTPSecret(secret string) (string, error) {
	if h.totpProtector == nil {
		return secret, nil
	}
	return h.totpProtector.Seal(secret)
}

func (h *PageHandler) openTOTPSecret(stored string) (string, error) {
	if h.totpProtector == nil {
		return stored, nil
	}
	return h.totpProtector.Open(stored)
}

func (h *PageHandler) logAudit(r *http.Request, userID int64, action audit.Action, statusCode int) {
	if h.auditRepo == nil {
		return
	}
	targetID := userID
	entry := audit.Entry{
		UserID:     userID,
		Action:     action,
		TargetType: "user",
		TargetID:   &targetID,
		IPAddress:  ExtractIP(r),
		UserAgent:  r.UserAgent(),
		StatusCode: statusCode,
	}
	if err := h.auditRepo.Log(r.Context(), entry); err != nil && h.logger != nil {
		h.logger.Error("web audit: log failed", "error", err, "action", action)
	}
}

// Login2FAPage shows the TOTP code input form.
func (h *PageHandler) Login2FAPage(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("pending_2fa")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderStandalone(w, h.tc, "login_2fa.html", map[string]interface{}{"Error": "", "CSRFToken": CSRFToken(r)})
}

// Login2FASubmit validates the TOTP code and completes login.
func (h *PageHandler) Login2FASubmit(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("pending_2fa")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := h.jwtSvc.ValidatePending2FAToken(cookie.Value)
	if err != nil {
		http.SetCookie(w, &http.Cookie{Name: "pending_2fa", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	code := r.FormValue("totp_code")
	recoveryCode := r.FormValue("recovery_code")

	var u user.User
	err = h.db.QueryRow(r.Context(),
		`SELECT id, username, email, password_hash, full_name, role, department, is_active,
		        COALESCE(totp_secret,''), COALESCE(totp_enabled,false), created_at, updated_at
		 FROM users WHERE id = $1`, userID,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.Role, &u.Department, &u.IsActive,
		&u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	valid := false
	if code != "" {
		secret, err := h.openTOTPSecret(u.TOTPSecret)
		if err != nil {
			if h.logger != nil {
				h.logger.Error("2fa login: decrypt totp secret", "error", err, "user_id", u.ID)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		valid = auth.ValidateTOTP(secret, code)
	} else if recoveryCode != "" {
		// Check recovery code
		var codeID int64
		err := h.db.QueryRow(r.Context(),
			`SELECT id FROM totp_recovery_codes WHERE user_id = $1 AND code = $2 AND used = false`,
			u.ID, recoveryCode).Scan(&codeID)
		if err == nil {
			h.db.Exec(r.Context(), `UPDATE totp_recovery_codes SET used = true WHERE id = $1`, codeID)
			valid = true
		}
	}

	if !valid {
		h.logAudit(r, u.ID, audit.ActionLogin, http.StatusUnauthorized)
		renderStandalone(w, h.tc, "login_2fa.html", map[string]interface{}{
			"Error": "Invalid verification code", "CSRFToken": CSRFToken(r),
		})
		return
	}

	// 2FA verified — clear pending cookie and issue session
	http.SetCookie(w, &http.Cookie{Name: "pending_2fa", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	h.rateLimiter.RecordSuccess(ExtractIP(r))
	h.issueSessionCookies(w, &u)
	h.logAudit(r, u.ID, audit.ActionLogin, http.StatusSeeOther)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// --- 2FA Setup/Manage ---

func (h *PageHandler) TwoFactorPage(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var totpEnabled bool
	h.db.QueryRow(r.Context(), `SELECT COALESCE(totp_enabled,false) FROM users WHERE id = $1`, u.ID).Scan(&totpEnabled)
	data := h.pageData(r, "2FA Settings", "account")
	data["TOTPEnabled"] = totpEnabled
	renderPage(w, h.tc, "totp_setup.html", data)
}

func (h *PageHandler) TwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := h.pageData(r, "2FA Setup", "account")
	data["SetupSecret"] = secret
	renderPage(w, h.tc, "totp_setup.html", data)
}

func (h *PageHandler) TwoFactorVerify(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	secret := r.FormValue("secret")
	code := r.FormValue("totp_code")

	if !auth.ValidateTOTP(secret, code) {
		data := h.pageData(r, "2FA Setup", "account")
		data["SetupSecret"] = secret
		data["Error"] = "Invalid code. Please try again."
		renderPage(w, h.tc, "totp_setup.html", data)
		return
	}

	protectedSecret, err := h.sealTOTPSecret(secret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Save secret and enable 2FA
	_, err = h.db.Exec(r.Context(),
		`UPDATE users SET totp_secret = $1, totp_enabled = true WHERE id = $2`, protectedSecret, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate recovery codes
	codes, _ := auth.GenerateRecoveryCodes()
	for _, code := range codes {
		h.db.Exec(r.Context(),
			`INSERT INTO totp_recovery_codes (user_id, code) VALUES ($1, $2)`, u.ID, code)
	}

	data := h.pageData(r, "2FA Enabled", "account")
	data["RecoveryCodes"] = codes
	renderPage(w, h.tc, "totp_setup.html", data)
}

func (h *PageHandler) TwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	code := r.FormValue("totp_code")

	// Load current secret
	var secret string
	h.db.QueryRow(r.Context(), `SELECT COALESCE(totp_secret,'') FROM users WHERE id = $1`, u.ID).Scan(&secret)
	secret, err := h.openTOTPSecret(secret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !auth.ValidateTOTP(secret, code) {
		data := h.pageData(r, "2FA Settings", "account")
		data["TOTPEnabled"] = true
		data["Error"] = "Invalid code"
		renderPage(w, h.tc, "totp_setup.html", data)
		return
	}

	h.db.Exec(r.Context(), `UPDATE users SET totp_secret = '', totp_enabled = false WHERE id = $1`, u.ID)
	h.db.Exec(r.Context(), `DELETE FROM totp_recovery_codes WHERE user_id = $1`, u.ID)

	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

// --- File Tracking ---

func (h *PageHandler) AdminTrackingPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	data := h.pageData(r, "File Tracking", "admin-tracking")
	if h.fileTracker != nil {
		files, _ := h.fileTracker.List(r.Context())
		detections, _ := h.fileTracker.GetAllDetections(r.Context(), 50)
		data["TrackedFiles"] = files
		data["Detections"] = detections
	}
	renderPage(w, h.tc, "admin_tracking.html", data)
}

func (h *PageHandler) AdminTrackingAdd(w http.ResponseWriter, r *http.Request) {
	u, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Calculate hashes by reading the file
	import_sha256 := sha256Hash(file)
	file.Seek(0, 0)
	import_md5 := md5Hash(file)

	sensitivity := r.FormValue("sensitivity")
	description := r.FormValue("description")

	if h.fileTracker != nil {
		h.fileTracker.Register(r.Context(), header.Filename, import_sha256, import_md5, sensitivity, description, u.ID)
	}

	http.Redirect(w, r, "/admin/tracking", http.StatusSeeOther)
}

func (h *PageHandler) AdminTrackingDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if h.fileTracker != nil {
		h.fileTracker.Unregister(r.Context(), id)
	}
	http.Redirect(w, r, "/admin/tracking", http.StatusSeeOther)
}

func (h *PageHandler) AdminTrackingDetections(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	data := h.pageData(r, "Detection History", "admin-tracking")
	if h.fileTracker != nil {
		detections, _ := h.fileTracker.GetDetections(r.Context(), id, 100)
		data["Detections"] = detections
		files, _ := h.fileTracker.List(r.Context())
		data["TrackedFiles"] = files
	}
	renderPage(w, h.tc, "admin_tracking.html", data)
}

func (h *PageHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		if claims, err := h.jwtSvc.ValidateAccessToken(cookie.Value); err == nil {
			h.logAudit(r, claims.UserID, audit.ActionLogout, http.StatusSeeOther)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "token", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
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

	// UEBA: top risky users
	var riskUsers []UserRiskSummary
	if h.uebaProvider != nil {
		riskUsers, _ = h.uebaProvider.GetTopRiskUsers(r.Context(), 5)
	}

	data := h.pageData(r, "Dashboard", "dashboard")
	data["Stats"] = dashStats{stats.TotalEvents, stats.TodayEvents, 0, len(alerts)}
	data["RecentLogs"] = recentLogs
	data["Alerts"] = alerts
	data["SuspiciousEvents"] = suspiciousEvents
	data["RiskUsers"] = riskUsers
	renderPage(w, h.tc, "dashboard.html", data)
}

func (h *PageHandler) FileBrowser(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var folderID *int64
	var currentFolderID int64
	if idStr := r.URL.Query().Get("folder_id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid folder ID", http.StatusBadRequest)
			return
		}
		folderID = &id
		currentFolderID = id
		if !h.requireFolderAccess(w, r, u, id, folder.PermRead) {
			return
		}
	}

	folders, err := h.folderRepo.ListChildren(r.Context(), folderID)
	if err != nil {
		h.logger.Error("file browser: list folders", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	folders, err = h.filterReadableFolders(r, u, folders)
	if err != nil {
		h.logger.Error("file browser: filter folders", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var files []*vault.File
	if folderID != nil {
		files, err = h.vaultRepo.ListFilesByFolder(r.Context(), *folderID)
		if err != nil {
			h.logger.Error("file browser: list files", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Build breadcrumb chain
	breadcrumbs := h.buildBreadcrumbs(r, folderID, u)

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
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !h.requireFolderAccess(w, r, u, file.FolderID, folder.PermRead) {
		return
	}

	versions, _ := h.vaultRepo.ListVersions(r.Context(), fileID)
	targetType := "file"
	auditLogs, _ := h.auditRepo.Search(r.Context(), audit.SearchParams{
		TargetType: &targetType, TargetID: &fileID, Limit: 20,
	})

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
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	f, err := h.vaultRepo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if !h.requireFolderAccess(w, r, u, f.FolderID, folder.PermRead) {
		return
	}

	targetType := "file"
	logs, _ := h.auditRepo.Search(r.Context(), audit.SearchParams{
		TargetType: &targetType, TargetID: &fileID, Limit: 100,
	})

	data := h.pageData(r, "File Audit", "audit-search")
	data["FileName"] = f.Name
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
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	users, _ := h.userRepo.List(r.Context())
	data := h.pageData(r, "User Management", "admin-users")
	data["Users"] = users
	renderPage(w, h.tc, "admin_users.html", data)
}

func (h *PageHandler) AdminUserEditPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

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
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	rules, _ := h.alertRepo.ListRules(r.Context(), false)
	alerts, _ := h.alertRepo.ListAlerts(r.Context(), false, 50, 0)

	data := h.pageData(r, "Alert Management", "admin-alerts")
	data["Rules"] = rules
	data["Alerts"] = alerts
	renderPage(w, h.tc, "admin_alerts.html", data)
}

func (h *PageHandler) AdminAgentsPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	type agentInfo struct {
		Hostname    string
		Source      string
		LastCheckin time.Time
		EventCount  int64
		IsOnline    bool
	}

	regAgents, _ := h.endpointRepo.ListAgents(r.Context())
	onlineWindow := 10 * time.Minute
	var agents []agentInfo
	offlineCount := 0
	for _, row := range regAgents {
		isOnline := row.IsActive && time.Since(row.LastCheckin) < onlineWindow
		if !isOnline {
			offlineCount++
		}
		agents = append(agents, agentInfo{
			Hostname:    row.Hostname,
			Source:      row.Source,
			LastCheckin: row.LastCheckin,
			EventCount:  row.EventCount,
			IsOnline:    isOnline,
		})
	}

	data := h.pageData(r, "Agent Status", "admin-agents")
	data["Agents"] = agents
	data["OfflineAgentCount"] = offlineCount
	data["AgentOnlineWindowMinutes"] = int(onlineWindow / time.Minute)
	data["PSKConfigured"] = h.pskConfigured
	data["AgentPSK"] = h.agentPSK
	scheme := "https"
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	data["ServerURL"] = scheme + "://" + r.Host
	data["RegisteredAgents"] = regAgents
	if allUsers, err := h.userRepo.List(r.Context()); err == nil {
		data["AllUsers"] = allUsers
	}
	renderPage(w, h.tc, "admin_agents.html", data)
}

// InstallPage (GET /admin/install) renders an in-app install page: the one-click
// download button plus the step-by-step visual guide, all inside the web app so
// the admin can reach everything from the navigation in one place.
func (h *PageHandler) InstallPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	data := h.pageData(r, "에이전트 설치", "admin-install")
	renderPage(w, h.tc, "admin_install.html", data)
}

// installBatTemplate is a one-click Windows installer. __SERVER__/__PSK__ are
// substituted per-request. It self-elevates, downloads the agent, removes the
// old service-mode install if present, and registers a per-user hidden logon
// task. Clipboard APIs are session-scoped on Windows, so the monitor must run
// in the interactive user's session rather than as a LocalSystem service.
const installBatTemplate = "@echo off\n" +
	"chcp 65001 >nul\n" +
	"net session >nul 2>&1\n" +
	"if %errorLevel% neq 0 (\n" +
	"  echo 관리자 권한이 필요합니다. 권한 요청 창에서 [예]를 눌러주세요...\n" +
	"  powershell -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"\n" +
	"  exit /b\n" +
	")\n" +
	"echo.\n" +
	"echo  DocVault 보안 에이전트를 설치합니다. 잠시만 기다려주세요...\n" +
	"echo.\n" +
	"set \"INSTALL_DIR=C:\\DocVault\"\n" +
	"set \"RUN_CMD=C:\\DocVault\\run-docvault-agent.cmd\"\n" +
	"set \"RUN_VBS=C:\\DocVault\\run-docvault-agent.vbs\"\n" +
	"if not exist \"%INSTALL_DIR%\" mkdir \"%INSTALL_DIR%\"\n" +
	"powershell -ExecutionPolicy Bypass -NoProfile -Command \"Invoke-WebRequest -Uri '__SERVER__/download/dvclip-windows-amd64.exe' -OutFile 'C:\\DocVault\\dvclip.exe'; Unblock-File 'C:\\DocVault\\dvclip.exe'\"\n" +
	"echo 기존 서비스 방식 설치를 정리합니다...\n" +
	"net stop DocVaultClipAgent >nul 2>&1\n" +
	"\"C:\\DocVault\\dvclip.exe\" uninstall >nul 2>&1\n" +
	"(\n" +
	"  echo @echo off\n" +
	"  echo set \"DOCVAULT_SERVER_URL=__SERVER__\"\n" +
	"  echo set \"DOCVAULT_AGENT_PSK=__PSK__\"\n" +
	"  echo :loop\n" +
	"  echo \"C:\\DocVault\\dvclip.exe\"\n" +
	"  echo timeout /t 5 /nobreak ^>nul\n" +
	"  echo goto loop\n" +
	") > \"%RUN_CMD%\"\n" +
	"(\n" +
	"  echo Set WshShell = CreateObject(\"WScript.Shell\")\n" +
	"  echo WshShell.Run \"cmd.exe /c \"\"%RUN_CMD%\"\"\", 0, False\n" +
	") > \"%RUN_VBS%\"\n" +
	"schtasks /Delete /TN \"DocVaultClipAgent\" /F >nul 2>&1\n" +
	"schtasks /Create /TN \"DocVaultClipAgent\" /SC ONLOGON /TR \"wscript.exe C:\\DocVault\\run-docvault-agent.vbs\" /RL LIMITED /F\n" +
	"schtasks /Run /TN \"DocVaultClipAgent\"\n" +
	"echo.\n" +
	"echo  ============================================\n" +
	"echo   설치 완료! 이 창을 닫으셔도 됩니다.\n" +
	"echo  ============================================\n" +
	"echo.\n" +
	"pause\n"

// AgentInstaller (GET /admin/agent-installer.bat) serves a one-click Windows
// installer with the server URL + PSK baked in. Admin-only (it contains the PSK).
func (h *PageHandler) AgentInstaller(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	scheme := "https"
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	serverURL := scheme + "://" + r.Host
	bat := strings.ReplaceAll(installBatTemplate, "__SERVER__", serverURL)
	bat = strings.ReplaceAll(bat, "__PSK__", h.agentPSK)
	bat = strings.ReplaceAll(bat, "\n", "\r\n")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="docvault-install.bat"`)
	_, _ = w.Write([]byte(bat))
}

func (h *PageHandler) EventsSearchPage(w http.ResponseWriter, r *http.Request) {
	filter := struct {
		UserID    int64
		UserIDStr string
		EventType string
		FileName  string
		From      string
		To        string
	}{
		EventType: r.URL.Query().Get("event_type"),
		FileName:  r.URL.Query().Get("file_name"),
		From:      r.URL.Query().Get("from"),
		To:        r.URL.Query().Get("to"),
		UserIDStr: r.URL.Query().Get("user_id"),
	}

	params := endpoint.SearchParams{Limit: 100}
	if filter.UserIDStr != "" {
		if id, err := strconv.ParseInt(filter.UserIDStr, 10, 64); err == nil {
			params.UserID = &id
			filter.UserID = id
		}
	}
	if filter.EventType != "" {
		et := endpoint.EventType(filter.EventType)
		params.EventType = &et
	}
	if filter.FileName != "" {
		params.FileName = &filter.FileName
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

	events, _ := h.endpointRepo.Search(r.Context(), params)
	users, _ := h.userRepo.List(r.Context())

	data := h.pageData(r, "Endpoint Events", "events")
	data["Events"] = events
	data["Users"] = users
	data["Filter"] = filter
	renderPage(w, h.tc, "events_search.html", data)
}

// ExportEventsCSV handles GET /api/events/export — legal evidence CSV export.
func (h *PageHandler) ExportEventsCSV(w http.ResponseWriter, r *http.Request) {
	params := endpoint.SearchParams{Limit: 50000}

	if v := r.URL.Query().Get("user_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			params.UserID = &id
		}
	}
	if v := r.URL.Query().Get("event_type"); v != "" {
		et := endpoint.EventType(v)
		params.EventType = &et
	}
	if v := r.URL.Query().Get("file_name"); v != "" {
		params.FileName = &v
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
			params.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
			params.To = &t
		}
	}

	events, err := h.endpointRepo.Search(r.Context(), params)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=endpoint_events_export.csv")

	// BOM for Excel Korean compatibility
	w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"일시", "사용자ID", "이벤트유형", "파일명", "파일경로", "프로세스", "호스트명", "소스"}); err != nil {
		h.logger.Error("export endpoint CSV header", "error", err)
		return
	}

	for _, e := range events {
		userID := ""
		if e.UserID != nil {
			userID = strconv.FormatInt(*e.UserID, 10)
		}
		if err := cw.Write([]string{
			e.EventTime.Format("2006-01-02 15:04:05"),
			userID,
			csvSafeField(string(e.EventType)),
			csvSafeField(e.FileName),
			csvSafeField(e.FilePath),
			csvSafeField(e.ProcessName),
			csvSafeField(e.Hostname),
			csvSafeField(e.Source),
		}); err != nil {
			h.logger.Error("export endpoint CSV row", "error", err)
			return
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		h.logger.Error("export endpoint CSV flush", "error", err)
	}
}

func csvSafeField(s string) string {
	if s == "" {
		return ""
	}
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed == "" {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

func (h *PageHandler) AdminMonitoringPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	data := h.pageData(r, "모니터링 설정", "admin-monitoring")

	if h.monitorHandler != nil {
		summary, err := h.monitorHandler.GetSummary(r.Context())
		if err != nil {
			h.logger.Error("admin monitoring page", "error", err)
		} else {
			data["Processes"] = summary.Processes
			data["Extensions"] = summary.Extensions
			data["Paths"] = summary.Paths
			data["DisguiseRules"] = summary.DisguiseRules
		}
	}

	renderPage(w, h.tc, "admin_monitoring.html", data)
}

// buildBreadcrumbs walks up the folder tree to build navigation breadcrumbs.
func (h *PageHandler) buildBreadcrumbs(r *http.Request, folderID *int64, u *auth.AuthUser) []folder.Folder {
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
		if allowed, err := h.hasFolderAccess(r, u, f.ID, folder.PermRead); err != nil || !allowed {
			break
		}
		crumbs = append([]folder.Folder{*f}, crumbs...)
		currentID = f.ParentID
	}
	return crumbs
}

func sha256Hash(r io.Reader) string {
	h := sha256.New()
	io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil))
}

func md5Hash(r io.ReadSeeker) string {
	h := md5.New()
	io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil))
}
