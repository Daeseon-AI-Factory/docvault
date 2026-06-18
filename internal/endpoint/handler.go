package endpoint

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/monitoring"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

// AlertEvaluator is called after storing an event to fire alert rules.
type AlertEvaluator interface {
	Evaluate(ctx context.Context, event *EndpointEvent)
}

// SSEBroadcaster pushes real-time events to connected dashboard clients.
type SSEBroadcaster interface {
	BroadcastEndpointEvent(eventType, hostname, fileName, processName string)
	BroadcastAlert(severity, message, hostname string)
}

// BehaviorAnalyzer evaluates user behavior against baselines.
type BehaviorAnalyzer interface {
	AnalyzeEvent(ctx context.Context, evt BehaviorEventContext) []BehaviorRiskFactor
}

// FileTracker checks if a file's hash matches any tracked file.
type FileTracker interface {
	CheckEvent(ctx context.Context, sha256, md5, hostname, foundPath, foundName, eventType, processName string, userID *int64) int64
}

// BehaviorEventContext is the data needed for behavior analysis.
type BehaviorEventContext struct {
	UserID      int64
	EventType   string
	FileName    string
	FilePath    string
	ProcessName string
	Hostname    string
	IPAddress   string
	EventTime   time.Time
}

// BehaviorRiskFactor is returned by the analyzer.
type BehaviorRiskFactor struct {
	Factor string
	Weight int
	Detail string
}

type Handler struct {
	repo             *Repository
	db               *pgxpool.Pool
	psk              string
	alertEvaluator   AlertEvaluator
	monCfgRepo       *monitoring.Repository
	sseBroadcaster   SSEBroadcaster
	behaviorAnalyzer BehaviorAnalyzer
	fileTracker      FileTracker
	logger           *slog.Logger
}

// SetFileTracker sets the hash-based file tracker.
func (h *Handler) SetFileTracker(tracker FileTracker) {
	h.fileTracker = tracker
}

// SetMonitoringConfig sets the monitoring config repository for DB-based lookups.
func (h *Handler) SetMonitoringConfig(monCfgRepo *monitoring.Repository) {
	h.monCfgRepo = monCfgRepo
}

// SetSSEHub sets the SSE broadcaster for real-time dashboard updates.
func (h *Handler) SetSSEHub(broadcaster SSEBroadcaster) {
	h.sseBroadcaster = broadcaster
}

// SetBehaviorAnalyzer sets the UEBA analyzer for real-time anomaly detection.
func (h *Handler) SetBehaviorAnalyzer(analyzer BehaviorAnalyzer) {
	h.behaviorAnalyzer = analyzer
}

func NewHandler(repo *Repository, db *pgxpool.Pool, psk string, alertEval AlertEvaluator, logger *slog.Logger) *Handler {
	return &Handler{
		repo:           repo,
		db:             db,
		psk:            psk,
		alertEvaluator: alertEval,
		logger:         logger,
	}
}

func (h *Handler) requirePSK(w http.ResponseWriter, r *http.Request, headerNames ...string) bool {
	if h.psk == "" {
		if h.logger != nil {
			h.logger.Error("agent endpoint requested without configured PSK")
		}
		http.Error(w, `{"error":"agent authentication is not configured"}`, http.StatusServiceUnavailable)
		return false
	}

	for _, name := range headerNames {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(name)), []byte(h.psk)) == 1 {
			return true
		}
	}

	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	return false
}

// lookupUserByHostname resolves hostname to user_id from endpoint_agents table.
func (h *Handler) lookupUserByHostname(ctx context.Context, hostname string) *int64 {
	var userID int64
	err := h.db.QueryRow(ctx,
		`SELECT user_id FROM endpoint_agents
		 WHERE hostname = $1 AND is_active = true AND user_id IS NOT NULL
		 ORDER BY last_checkin DESC LIMIT 1`, hostname,
	).Scan(&userID)
	if err != nil {
		return nil
	}
	return &userID
}

// buildHostnameMap builds a hostname→userID map for a batch of events.
func (h *Handler) buildHostnameMap(ctx context.Context, hostnames []string) map[string]int64 {
	m := make(map[string]int64)
	for _, hostname := range hostnames {
		if uid := h.lookupUserByHostname(ctx, hostname); uid != nil {
			m[hostname] = *uid
		}
	}
	return m
}

// ReceiveOsquery handles POST /api/events/osquery
func (h *Handler) ReceiveOsquery(w http.ResponseWriter, r *http.Request) {
	if !h.requirePSK(w, r, "X-Osquery-PSK") {
		return
	}

	var batch OsqueryBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	count, err := h.processOsqueryBatch(r.Context(), &batch)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"received": count,
	})
}

// processOsqueryBatch normalizes, stores, and fans out a batch of osquery
// results. Shared by the legacy PSK-header endpoint (ReceiveOsquery) and the
// osquery TLS logger endpoint (OsqueryLog). Returns the number of stored events.
func (h *Handler) processOsqueryBatch(ctx context.Context, batch *OsqueryBatch) (int, error) {
	if len(batch.Results) == 0 {
		return 0, nil
	}

	// Collect unique hostnames
	hostSet := make(map[string]bool)
	for _, res := range batch.Results {
		hostSet[res.HostIdentifier] = true
	}
	var hostnames []string
	for hn := range hostSet {
		hostnames = append(hostnames, hn)
	}

	hostnameMap := h.buildHostnameMap(ctx, hostnames)
	for _, hostname := range hostnames {
		if err := h.repo.TouchAgent(ctx, hostname, "osquery", "", ""); err != nil {
			h.logger.Warn("touch osquery agent", "hostname", hostname, "error", err)
		}
	}

	// Use DB-based disguise checker if available
	var checker ExtensionDisguiseChecker
	if h.monCfgRepo != nil {
		if cfg, err := h.monCfgRepo.Get(ctx); err == nil {
			checker = cfg
		}
	}
	events := NormalizeOsqueryEventsWithChecker(batch, hostnameMap, checker)

	if err := h.repo.InsertBatch(ctx, events); err != nil {
		h.logger.Error("process osquery events", "error", err, "count", len(events))
		return 0, err
	}

	// Evaluate alert rules + broadcast to dashboards
	for _, event := range events {
		if h.alertEvaluator != nil {
			h.alertEvaluator.Evaluate(ctx, event)
		}
		if h.sseBroadcaster != nil {
			h.sseBroadcaster.BroadcastEndpointEvent(string(event.EventType), event.Hostname, event.FileName, event.ProcessName)
		}
		if h.behaviorAnalyzer != nil && event.UserID != nil {
			h.behaviorAnalyzer.AnalyzeEvent(ctx, BehaviorEventContext{
				UserID: *event.UserID, EventType: string(event.EventType),
				FileName: event.FileName, FilePath: event.FilePath,
				ProcessName: event.ProcessName, Hostname: event.Hostname,
				EventTime: event.EventTime,
			})
		}
		// Hash-based file tracking
		if h.fileTracker != nil && event.Detail != nil {
			var detail map[string]string
			if err := json.Unmarshal(event.Detail, &detail); err == nil {
				sha256 := detail["sha256"]
				md5 := detail["md5"]
				if sha256 != "" || md5 != "" {
					h.fileTracker.CheckEvent(ctx, sha256, md5,
						event.Hostname, event.FilePath, event.FileName,
						string(event.EventType), event.ProcessName, event.UserID)
				}
			}
		}
	}

	h.logger.Info("processed osquery events", "count", len(events))
	return len(events), nil
}

// ReceiveClipboard handles POST /api/events/clipboard
func (h *Handler) ReceiveClipboard(w http.ResponseWriter, r *http.Request) {
	if !h.requirePSK(w, r, "X-Agent-PSK") {
		return
	}

	var ce ClipboardEvent
	if err := json.NewDecoder(r.Body).Decode(&ce); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	userID, err := h.autoResolveEndpointUserID(r.Context(), ce.Username)
	if err != nil && h.logger != nil {
		h.logger.Warn("auto resolve clipboard user", "hostname", ce.Hostname, "username", ce.Username, "error", err)
	}
	if err := h.repo.TouchAgent(r.Context(), ce.Hostname, "clipboard", ce.Username, clientIP(r)); err != nil {
		h.logger.Warn("touch clipboard agent", "hostname", ce.Hostname, "error", err)
	}
	h.assignEndpointAgentIfUnassigned(r.Context(), ce.Hostname, userID)
	hostnameMap := h.buildHostnameMap(r.Context(), []string{ce.Hostname})
	event := NormalizeClipboardEvent(&ce, hostnameMap)

	if err := h.repo.Insert(r.Context(), event); err != nil {
		h.logger.Error("receive clipboard event", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Evaluate alert rules + broadcast
	if h.alertEvaluator != nil {
		h.alertEvaluator.Evaluate(r.Context(), event)
	}
	if h.sseBroadcaster != nil {
		h.sseBroadcaster.BroadcastEndpointEvent(string(event.EventType), event.Hostname, event.FileName, event.ProcessName)
	}
	if h.behaviorAnalyzer != nil && event.UserID != nil {
		h.behaviorAnalyzer.AnalyzeEvent(r.Context(), BehaviorEventContext{
			UserID: *event.UserID, EventType: string(event.EventType),
			FileName: event.FileName, Hostname: event.Hostname,
			EventTime: event.EventTime,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

// ReceiveHeartbeat handles POST /api/heartbeat and refreshes agent liveness
// without inserting a user activity event.
func (h *Handler) ReceiveHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !h.requirePSK(w, r, "X-Agent-PSK") {
		return
	}

	var req struct {
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		Source   string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Hostname == "" {
		http.Error(w, `{"error":"hostname is required"}`, http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		req.Source = "clipboard"
	}
	if req.Source != "clipboard" && req.Source != "osquery" {
		http.Error(w, `{"error":"invalid source"}`, http.StatusBadRequest)
		return
	}
	if h.repo == nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	userID, err := h.autoResolveEndpointUserID(r.Context(), req.Username)
	if err != nil && h.logger != nil {
		h.logger.Warn("auto resolve heartbeat user", "hostname", req.Hostname, "username", req.Username, "error", err)
	}
	if err := h.repo.TouchAgent(r.Context(), req.Hostname, req.Source, req.Username, clientIP(r)); err != nil {
		if h.logger != nil {
			h.logger.Warn("heartbeat touch agent", "hostname", req.Hostname, "source", req.Source, "error", err)
		}
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	h.assignEndpointAgentIfUnassigned(r.Context(), req.Hostname, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"hostname": req.Hostname,
	})
}

// Enroll handles POST /api/enroll — registers an agent's hostname-to-user mapping.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	if !h.requirePSK(w, r, "X-Agent-PSK", "X-Osquery-PSK") {
		return
	}

	var req struct {
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		Source   string `json:"source"` // "osquery" or "clipboard"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Hostname == "" {
		http.Error(w, `{"error":"hostname is required"}`, http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		req.Source = "osquery"
	}

	userID, err := h.autoResolveEndpointUserID(r.Context(), req.Username)
	if err != nil && h.logger != nil {
		h.logger.Warn("auto resolve enrolled user", "hostname", req.Hostname, "username", req.Username, "error", err)
	}

	// Upsert endpoint_agents
	_, err = h.db.Exec(r.Context(),
		`INSERT INTO endpoint_agents (hostname, user_id, source, reported_username, last_ip, last_checkin)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (hostname, source)
		 DO UPDATE SET user_id = COALESCE(endpoint_agents.user_id, $2),
		               reported_username = COALESCE(NULLIF($4, ''), endpoint_agents.reported_username),
		               last_ip = COALESCE(NULLIF($5, ''), endpoint_agents.last_ip),
		               last_checkin = NOW(),
		               is_active = true`,
		req.Hostname, userID, req.Source, req.Username, clientIP(r),
	)
	if err != nil {
		h.logger.Error("enroll agent", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	h.logger.Info("agent enrolled", "hostname", req.Hostname, "source", req.Source, "user_id", userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "enrolled",
		"hostname": req.Hostname,
	})
}

func (h *Handler) autoResolveEndpointUserID(ctx context.Context, reportedUsername string) (*int64, error) {
	if h == nil || h.db == nil {
		return nil, nil
	}
	username := endpointUsernameCandidate(reportedUsername)
	if !isAutoAssignableEndpointUsername(username) {
		return nil, nil
	}

	var uid int64
	err := h.db.QueryRow(ctx,
		`SELECT id FROM users WHERE LOWER(username) = LOWER($1) ORDER BY id LIMIT 1`,
		username,
	).Scan(&uid)
	if err == nil {
		return &uid, nil
	}

	email := autoEndpointEmail(username)
	err = h.db.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, full_name, role, department)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
		 RETURNING id`,
		username, email, "endpoint-auto-user-no-login", username, string(user.RoleEmployee), "자동 등록",
	).Scan(&uid)
	if err != nil {
		return nil, err
	}
	if h.logger != nil {
		h.logger.Info("auto-created endpoint user", "username", username, "user_id", uid)
	}
	return &uid, nil
}

func (h *Handler) assignEndpointAgentIfUnassigned(ctx context.Context, hostname string, userID *int64) {
	if h == nil || h.db == nil || userID == nil || strings.TrimSpace(hostname) == "" {
		return
	}
	if _, err := h.db.Exec(ctx,
		`UPDATE endpoint_agents SET user_id = COALESCE(user_id, $2) WHERE hostname = $1`,
		hostname, *userID,
	); err != nil && h.logger != nil {
		h.logger.Warn("auto assign endpoint agent", "hostname", hostname, "user_id", *userID, "error", err)
	}
}

func endpointUsernameCandidate(reportedUsername string) string {
	u := strings.TrimSpace(reportedUsername)
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.LastIndex(u, "/"); i >= 0 {
		u = u[i+1:]
	}
	return strings.TrimSpace(u)
}

func isAutoAssignableEndpointUsername(username string) bool {
	u := strings.TrimSpace(username)
	if u == "" || len([]rune(u)) > 50 || strings.HasSuffix(u, "$") {
		return false
	}
	switch strings.ToUpper(u) {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DEFAULTUSER0", "WDAGUTILITYACCOUNT":
		return false
	default:
		return true
	}
}

func autoEndpointEmail(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(username)))
	return "endpoint-" + hex.EncodeToString(sum[:])[:16] + "@docvault.local"
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if i := strings.IndexByte(forwarded, ','); i >= 0 {
			forwarded = forwarded[:i]
		}
		return strings.TrimSpace(forwarded)
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// AgentConfig handles POST /api/config — serves dynamic osquery config from DB.
func (h *Handler) AgentConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requirePSK(w, r, "X-Osquery-PSK") {
		return
	}

	cfg := h.buildOsqueryConfig(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// buildOsqueryConfig generates osquery config dynamically from DB monitoring settings.
func (h *Handler) buildOsqueryConfig(ctx context.Context) map[string]interface{} {
	schedule := map[string]interface{}{
		"file_events": map[string]interface{}{
			"query":    "SELECT target_path, action, time, md5, sha256 FROM file_events;",
			"interval": 30,
			"removed":  false,
		},
		"usb_devices": map[string]interface{}{
			"query":    "SELECT vendor, model, serial, removable FROM usb_devices WHERE removable = 1;",
			"interval": 60,
		},
		"process_events": map[string]interface{}{
			"query":    "SELECT pid, path, cmdline, parent, time FROM process_events WHERE path NOT LIKE 'C:\\Windows\\%';",
			"interval": 30,
			"removed":  false,
		},
		"extension_rename_detect": map[string]interface{}{
			"query":    "SELECT target_path, action, time, md5 FROM file_events WHERE action = 'MOVED' OR action = 'RENAMED';",
			"interval": 15,
			"removed":  false,
		},
	}

	if h.monCfgRepo == nil {
		return map[string]interface{}{"schedule": schedule, "node_invalid": false}
	}

	monCfg, err := h.monCfgRepo.Get(ctx)
	if err != nil {
		return map[string]interface{}{"schedule": schedule, "node_invalid": false}
	}

	// Build extension filter for SQL LIKE clauses
	var extLikes []string
	for _, ext := range monCfg.Extensions {
		if ext.IsSensitive {
			extLikes = append(extLikes, fmt.Sprintf("pof.path LIKE '%%%s'", ext.Extension))
		}
	}
	extFilter := strings.Join(extLikes, " OR ")
	if extFilter == "" {
		extFilter = "1=0"
	}

	// Messenger file access query (built from DB process groups)
	messengerNames := monCfg.ProcessNamesForGroup("messenger")
	if len(messengerNames) > 0 {
		var nameList []string
		for _, n := range messengerNames {
			nameList = append(nameList, fmt.Sprintf("'%s'", n))
		}
		schedule["messenger_file_access"] = map[string]interface{}{
			"query": fmt.Sprintf(
				"SELECT pof.pid, p.path, p.name, pof.path AS accessed_file FROM process_open_files pof JOIN processes p ON pof.pid = p.pid WHERE p.name IN (%s) AND (%s);",
				strings.Join(nameList, ","), extFilter),
			"interval": 15,
		}
	}

	// Email file access query
	emailNames := monCfg.ProcessNamesForGroup("email")
	if len(emailNames) > 0 {
		var nameList []string
		for _, n := range emailNames {
			nameList = append(nameList, fmt.Sprintf("'%s'", n))
		}
		schedule["email_file_access"] = map[string]interface{}{
			"query": fmt.Sprintf(
				"SELECT pof.pid, p.path, p.name, pof.path AS accessed_file FROM process_open_files pof JOIN processes p ON pof.pid = p.pid WHERE p.name IN (%s) AND (%s);",
				strings.Join(nameList, ","), extFilter),
			"interval": 15,
		}
	}

	// Browser/cloud upload query
	browserNames := monCfg.ProcessNamesForGroup("browser")
	if len(browserNames) > 0 {
		var nameList []string
		for _, n := range browserNames {
			nameList = append(nameList, fmt.Sprintf("'%s'", n))
		}
		schedule["cloud_upload_access"] = map[string]interface{}{
			"query": fmt.Sprintf(
				"SELECT pof.pid, p.path, p.name, pof.path AS accessed_file FROM process_open_files pof JOIN processes p ON pof.pid = p.pid WHERE p.name IN (%s) AND (%s) AND pof.path NOT LIKE '%%Cache%%' AND pof.path NOT LIKE '%%Temp%%';",
				strings.Join(nameList, ","), extFilter),
			"interval": 30,
		}
	}

	// Screen capture query
	captureNames := monCfg.ProcessNamesForGroup("screen_capture")
	if len(captureNames) > 0 {
		var nameList []string
		for _, n := range captureNames {
			nameList = append(nameList, fmt.Sprintf("'%s'", n))
		}
		schedule["screen_capture_detect"] = map[string]interface{}{
			"query": fmt.Sprintf(
				"SELECT pid, path, name, cmdline FROM processes WHERE name IN (%s);",
				strings.Join(nameList, ",")),
			"interval": 30,
		}
	}

	// Removable drive copy query (from monitored paths)
	removablePaths := monCfg.PathsForType("removable")
	if len(removablePaths) > 0 {
		var pathLikes []string
		for _, p := range removablePaths {
			// Convert glob pattern to SQL LIKE: "E:\%%" -> "E:\%"
			sqlPath := strings.ReplaceAll(p, "%%", "%")
			pathLikes = append(pathLikes, fmt.Sprintf("target_path LIKE '%s'", sqlPath))
		}
		schedule["removable_drive_file_copy"] = map[string]interface{}{
			"query": fmt.Sprintf(
				"SELECT target_path, action, time, md5, sha256 FROM file_events WHERE (%s) AND action IN ('CREATED','UPDATED');",
				strings.Join(pathLikes, " OR ")),
			"interval": 15,
			"removed":  false,
		}
	}

	// Network share copy query
	schedule["network_share_copy"] = map[string]interface{}{
		"query":    "SELECT target_path, action, time, md5 FROM file_events WHERE target_path LIKE '\\\\\\\\%' AND action IN ('CREATED','UPDATED');",
		"interval": 30,
		"removed":  false,
	}

	// Print job query
	schedule["print_jobs"] = map[string]interface{}{
		"query":    "SELECT pof.pid, p.name, p.path, pof.path AS spool_file FROM process_open_files pof JOIN processes p ON pof.pid = p.pid WHERE p.name = 'spoolsv.exe' AND pof.path LIKE '%.SPL';",
		"interval": 30,
	}

	// Build file_paths from DB
	filePaths := make(map[string][]string)
	for _, p := range monCfg.Paths {
		filePaths["monitored_"+p.PathType] = append(filePaths["monitored_"+p.PathType], p.PathPattern)
	}

	return map[string]interface{}{
		"schedule":     schedule,
		"file_paths":   filePaths,
		"node_invalid": false,
	}
}

// SearchEvents handles GET /api/events/search
func (h *Handler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	params := SearchParams{}

	if v := r.URL.Query().Get("user_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			params.UserID = &id
		}
	}
	if v := r.URL.Query().Get("hostname"); v != "" {
		params.Hostname = &v
	}
	if v := r.URL.Query().Get("event_type"); v != "" {
		et := EventType(v)
		params.EventType = &et
	}
	if v := r.URL.Query().Get("file_name"); v != "" {
		params.FileName = &v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		params.Source = &v
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.To = &t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			params.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			params.Offset = n
		}
	}

	events, err := h.repo.Search(r.Context(), params)
	if err != nil {
		h.logger.Error("search events", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
}

// UnifiedTimeline handles GET /api/timeline/{userID}
func (h *Handler) UnifiedTimeline(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid user ID"}`, http.StatusBadRequest)
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	entries, err := h.repo.UnifiedTimeline(r.Context(), userID, limit, offset)
	if err != nil {
		h.logger.Error("unified timeline", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"timeline": entries})
}
