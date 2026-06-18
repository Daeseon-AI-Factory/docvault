package endpoint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Insert(ctx context.Context, e *EndpointEvent) error {
	var detail []byte
	if e.Detail != nil {
		detail = e.Detail
	}

	err := r.db.QueryRow(ctx,
		`INSERT INTO endpoint_events (user_id, hostname, event_type, file_name, file_path, process_name, detail, source, event_time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, received_at`,
		e.UserID, e.Hostname, e.EventType, e.FileName, e.FilePath, e.ProcessName, detail, e.Source, e.EventTime,
	).Scan(&e.ID, &e.ReceivedAt)
	if err != nil {
		return fmt.Errorf("insert endpoint event: %w", err)
	}
	return nil
}

func (r *Repository) InsertBatch(ctx context.Context, events []*EndpointEvent) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, e := range events {
		var detail []byte
		if e.Detail != nil {
			detail = e.Detail
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO endpoint_events (user_id, hostname, event_type, file_name, file_path, process_name, detail, source, event_time)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			e.UserID, e.Hostname, e.EventType, e.FileName, e.FilePath, e.ProcessName, detail, e.Source, e.EventTime,
		)
		if err != nil {
			return fmt.Errorf("insert event in batch: %w", err)
		}
	}

	return tx.Commit(ctx)
}

type SearchParams struct {
	UserID    *int64
	Hostname  *string
	EventType *EventType
	FileName  *string
	Source    *string
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

func (r *Repository) Search(ctx context.Context, params SearchParams) ([]*EndpointEvent, error) {
	query := `SELECT id, user_id, hostname, event_type, file_name, file_path, process_name, detail, source, event_time, received_at
	          FROM endpoint_events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if params.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, *params.UserID)
		argIdx++
	}
	if params.Hostname != nil {
		query += fmt.Sprintf(" AND hostname ILIKE $%d", argIdx)
		args = append(args, "%"+*params.Hostname+"%")
		argIdx++
	}
	if params.EventType != nil {
		query += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, *params.EventType)
		argIdx++
	}
	if params.FileName != nil {
		query += fmt.Sprintf(" AND file_name ILIKE $%d", argIdx)
		args = append(args, "%"+*params.FileName+"%")
		argIdx++
	}
	if params.Source != nil {
		query += fmt.Sprintf(" AND source = $%d", argIdx)
		args = append(args, *params.Source)
		argIdx++
	}
	if params.From != nil {
		query += fmt.Sprintf(" AND event_time >= $%d", argIdx)
		args = append(args, *params.From)
		argIdx++
	}
	if params.To != nil {
		query += fmt.Sprintf(" AND event_time <= $%d", argIdx)
		args = append(args, *params.To)
		argIdx++
	}

	query += " ORDER BY event_time DESC"

	if params.Limit <= 0 {
		params.Limit = 50
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, params.Limit)
	argIdx++

	if params.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, params.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search endpoint events: %w", err)
	}
	defer rows.Close()

	var events []*EndpointEvent
	for rows.Next() {
		var e EndpointEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.Hostname, &e.EventType, &e.FileName, &e.FilePath,
			&e.ProcessName, &e.Detail, &e.Source, &e.EventTime, &e.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan endpoint event: %w", err)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// SearchByType returns recent events of a specific type from the last 24 hours.
func (r *Repository) SearchByType(ctx context.Context, eventType EventType, limit int) ([]*EndpointEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, user_id, hostname, event_type, file_name, file_path, process_name, detail, source, event_time, received_at
		 FROM endpoint_events
		 WHERE event_type = $1 AND event_time >= NOW() - INTERVAL '24 hours'
		 ORDER BY event_time DESC LIMIT $2`,
		eventType, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search by type %s: %w", eventType, err)
	}
	defer rows.Close()

	var events []*EndpointEvent
	for rows.Next() {
		var e EndpointEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.Hostname, &e.EventType, &e.FileName, &e.FilePath,
			&e.ProcessName, &e.Detail, &e.Source, &e.EventTime, &e.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan endpoint event: %w", err)
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// UnifiedTimeline merges audit_logs and endpoint_events for a user.
type TimelineEntry struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	FileName  string          `json:"file_name"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	IPAddress *string         `json:"ip_address,omitempty"`
}

func (r *Repository) UnifiedTimeline(ctx context.Context, userID int64, limit, offset int) ([]*TimelineEntry, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(ctx,
		`SELECT * FROM (
			SELECT created_at as ts, 'WEB' as source, action as event_type,
			       target_name as file_name, detail, ip_address
			FROM audit_logs WHERE user_id = $1
			UNION ALL
			SELECT event_time as ts, 'ENDPOINT' as source, event_type,
			       file_name, detail, NULL as ip_address
			FROM endpoint_events WHERE user_id = $1
		) combined
		ORDER BY ts DESC
		LIMIT $2 OFFSET $3`,
		userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("unified timeline for user %d: %w", userID, err)
	}
	defer rows.Close()

	var entries []*TimelineEntry
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.Timestamp, &e.Source, &e.EventType, &e.FileName, &e.Detail, &e.IPAddress); err != nil {
			return nil, fmt.Errorf("scan timeline entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// AgentRow is a registered endpoint agent joined with its assigned user.
type AgentRow struct {
	ID                   int64
	Hostname             string
	Source               string
	UserID               *int64
	Username             *string
	FullName             *string
	ReportedUsername     string
	LastIP               string
	IsActive             bool
	LastCheckin          time.Time
	EventCount           int64
	InstallTokenID       *int64
	AgentVersion         string
	RunningMode          string
	SessionUser          string
	HealthStatus         string
	ClipboardAvailable   *bool
	ClipboardError       string
	LastSelfTestAt       *time.Time
	LastClipboardEventAt *time.Time
}

// TouchAgent records that an agent was just seen. Event posts, osquery config
// polls, and explicit enrolls all count as liveness; otherwise an idle but
// healthy agent can look offline just because there were no suspicious events.
func (r *Repository) TouchAgent(ctx context.Context, hostname, source, reportedUsername, lastIP string) error {
	if hostname == "" || source == "" {
		return nil
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO endpoint_agents (hostname, source, reported_username, last_ip, last_checkin, is_active)
		 VALUES ($1, $2, $3, $4, NOW(), true)
		 ON CONFLICT (hostname, source)
		 DO UPDATE SET reported_username = COALESCE(NULLIF($3, ''), endpoint_agents.reported_username),
		               last_ip = COALESCE(NULLIF($4, ''), endpoint_agents.last_ip),
		               last_checkin = NOW(),
		               is_active = true`,
		hostname, source, reportedUsername, lastIP,
	)
	if err != nil {
		return fmt.Errorf("touch agent %s/%s: %w", hostname, source, err)
	}
	return nil
}

// ListAgents returns all registered agents with their assigned user (if any) and
// a 24h event count, most recently seen first.
func (r *Repository) ListAgents(ctx context.Context) ([]*AgentRow, error) {
	rows, err := r.db.Query(ctx,
		`SELECT a.id, a.hostname, a.source, a.user_id, u.username, u.full_name,
		        a.reported_username, a.last_ip, a.is_active, a.last_checkin,
		        COALESCE((SELECT COUNT(*) FROM endpoint_events e
		                  WHERE e.hostname = a.hostname AND e.event_time >= NOW() - INTERVAL '24 hours'), 0) AS cnt,
		        a.install_token_id, a.agent_version, a.running_mode, a.session_username,
		        a.health_status, a.clipboard_available, a.clipboard_error,
		        a.last_self_test_at, a.last_clipboard_event_at
		 FROM endpoint_agents a
		 LEFT JOIN users u ON u.id = a.user_id
		 ORDER BY a.last_checkin DESC`)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var out []*AgentRow
	for rows.Next() {
		var a AgentRow
		var clipboardAvailable sql.NullBool
		var installTokenID sql.NullInt64
		var lastSelfTestAt, lastClipboardEventAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Source, &a.UserID, &a.Username, &a.FullName,
			&a.ReportedUsername, &a.LastIP, &a.IsActive, &a.LastCheckin, &a.EventCount,
			&installTokenID, &a.AgentVersion, &a.RunningMode, &a.SessionUser,
			&a.HealthStatus, &clipboardAvailable, &a.ClipboardError,
			&lastSelfTestAt, &lastClipboardEventAt); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		if installTokenID.Valid {
			a.InstallTokenID = &installTokenID.Int64
		}
		if clipboardAvailable.Valid {
			v := clipboardAvailable.Bool
			a.ClipboardAvailable = &v
		}
		if lastSelfTestAt.Valid {
			t := lastSelfTestAt.Time
			a.LastSelfTestAt = &t
		}
		if lastClipboardEventAt.Valid {
			t := lastClipboardEventAt.Time
			a.LastClipboardEventAt = &t
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// AssignAgent sets (or clears, when userID is nil) the employee for a registered
// agent. Endpoint events are immutable hash-chained records, so assignment only
// affects the endpoint_agents mapping used for future event attribution.
func (r *Repository) AssignAgent(ctx context.Context, agentID int64, userID *int64) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin assign tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var hostname string
	if err := tx.QueryRow(ctx,
		`SELECT hostname FROM endpoint_agents WHERE id = $1`, agentID,
	).Scan(&hostname); err != nil {
		return fmt.Errorf("find agent %d: %w", agentID, err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE endpoint_agents SET user_id = $1 WHERE hostname = $2`,
		userID, hostname,
	); err != nil {
		return fmt.Errorf("assign host %s: %w", hostname, err)
	}
	return tx.Commit(ctx)
}

// AssignHostname sets (or clears) the employee for all agent rows belonging to
// a hostname. Windows onboarding thinks in PCs, while clipboard/osquery can
// create separate source rows for the same host.
func (r *Repository) AssignHostname(ctx context.Context, hostname string, userID *int64) error {
	if hostname == "" {
		return nil
	}
	_, err := r.db.Exec(ctx,
		`UPDATE endpoint_agents SET user_id = $1 WHERE hostname = $2`,
		userID, hostname,
	)
	if err != nil {
		return fmt.Errorf("assign hostname %s: %w", hostname, err)
	}
	return nil
}

type AgentHealthUpdate struct {
	Hostname           string
	Source             string
	Username           string
	LastIP             string
	InstallTokenID     *int64
	AgentVersion       string
	RunningMode        string
	SessionUser        string
	HealthStatus       string
	ClipboardAvailable bool
	ClipboardError     string
}

func (r *Repository) UpdateAgentHealth(ctx context.Context, h AgentHealthUpdate) (int64, error) {
	if h.Hostname == "" {
		return 0, fmt.Errorf("hostname is required")
	}
	if h.Source == "" {
		h.Source = "clipboard"
	}
	if h.HealthStatus == "" {
		h.HealthStatus = "installed"
	}
	var id int64
	err := r.db.QueryRow(ctx,
		`INSERT INTO endpoint_agents
		 (hostname, source, reported_username, last_ip, install_token_id, agent_version,
		  running_mode, session_username, health_status, clipboard_available, clipboard_error,
		  last_self_test_at, last_checkin, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), true)
		 ON CONFLICT (hostname, source)
		 DO UPDATE SET reported_username = COALESCE(NULLIF($3, ''), endpoint_agents.reported_username),
		               last_ip = COALESCE(NULLIF($4, ''), endpoint_agents.last_ip),
		               install_token_id = COALESCE($5, endpoint_agents.install_token_id),
		               agent_version = COALESCE(NULLIF($6, ''), endpoint_agents.agent_version),
		               running_mode = COALESCE(NULLIF($7, ''), endpoint_agents.running_mode),
		               session_username = COALESCE(NULLIF($8, ''), endpoint_agents.session_username),
		               health_status = CASE
		                   WHEN endpoint_agents.last_clipboard_event_at IS NOT NULL AND $9 = 'capture_waiting'
		                   THEN endpoint_agents.health_status
		                   ELSE $9
		               END,
		               clipboard_available = $10,
		               clipboard_error = $11,
		               last_self_test_at = NOW(),
		               last_checkin = NOW(),
		               is_active = true
		 RETURNING id`,
		h.Hostname, h.Source, h.Username, h.LastIP, h.InstallTokenID, h.AgentVersion,
		h.RunningMode, h.SessionUser, h.HealthStatus, h.ClipboardAvailable, h.ClipboardError,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("update agent health %s/%s: %w", h.Hostname, h.Source, err)
	}
	return id, nil
}

func (r *Repository) RecordClipboardCapture(ctx context.Context, hostname string) error {
	if hostname == "" {
		return nil
	}
	_, err := r.db.Exec(ctx,
		`UPDATE endpoint_agents
		 SET last_clipboard_event_at = NOW(), health_status = 'capture_ok'
		 WHERE hostname = $1 AND source = 'clipboard'`,
		hostname,
	)
	if err != nil {
		return fmt.Errorf("record clipboard capture %s: %w", hostname, err)
	}
	return nil
}

type OnboardingSummary struct {
	UnassignedAgents        int64
	OfflineAgents           int64
	CaptureUnverifiedAgents int64
	ProblemAgents           int64
	MachineUserAgents       int64
	ActiveInstallTokens     int64
}

func (r *Repository) OnboardingSummary(ctx context.Context, onlineWindow time.Duration) (*OnboardingSummary, error) {
	if onlineWindow <= 0 {
		onlineWindow = 10 * time.Minute
	}
	minutes := int(onlineWindow / time.Minute)
	if minutes <= 0 {
		minutes = 10
	}
	var s OnboardingSummary
	err := r.db.QueryRow(ctx,
		`SELECT
		    COALESCE(COUNT(*) FILTER (WHERE user_id IS NULL), 0),
		    COALESCE(COUNT(*) FILTER (WHERE is_active = false OR last_checkin < NOW() - make_interval(mins => $1)), 0),
		    COALESCE(COUNT(*) FILTER (WHERE source = 'clipboard' AND last_clipboard_event_at IS NULL), 0),
		    COALESCE(COUNT(*) FILTER (WHERE health_status = 'problem' OR clipboard_available = false), 0),
		    COALESCE(COUNT(*) FILTER (WHERE reported_username LIKE '%$'), 0),
		    COALESCE((SELECT COUNT(*) FROM install_tokens
		              WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()), 0)
		 FROM endpoint_agents`,
		minutes,
	).Scan(&s.UnassignedAgents, &s.OfflineAgents, &s.CaptureUnverifiedAgents,
		&s.ProblemAgents, &s.MachineUserAgents, &s.ActiveInstallTokens)
	if err != nil {
		return nil, fmt.Errorf("onboarding summary: %w", err)
	}
	return &s, nil
}

type InstallTokenRow struct {
	ID               int64
	UserID           *int64
	Username         string
	FullName         string
	CreatedBy        *int64
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LastDownloadedAt *time.Time
	UsedAt           *time.Time
	UsedHostname     string
	RevokedAt        *time.Time
}

func HashInstallToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (r *Repository) CreateInstallToken(ctx context.Context, rawToken string, userID *int64, createdBy int64, expiresAt time.Time) (int64, error) {
	var id int64
	err := r.db.QueryRow(ctx,
		`INSERT INTO install_tokens (token_hash, user_id, created_by, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		HashInstallToken(rawToken), userID, createdBy, expiresAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create install token: %w", err)
	}
	return id, nil
}

func (r *Repository) ListInstallTokens(ctx context.Context, limit int) ([]InstallTokenRow, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx,
		`SELECT t.id, t.user_id, COALESCE(u.username, ''), COALESCE(u.full_name, ''),
		        t.created_by, t.created_at, t.expires_at, t.last_downloaded_at,
		        t.used_at, t.used_hostname, t.revoked_at
		 FROM install_tokens t
		 LEFT JOIN users u ON u.id = t.user_id
		 ORDER BY t.created_at DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list install tokens: %w", err)
	}
	defer rows.Close()

	var out []InstallTokenRow
	for rows.Next() {
		row, err := scanInstallTokenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *Repository) GetUsableInstallToken(ctx context.Context, rawToken string) (*InstallTokenRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT t.id, t.user_id, COALESCE(u.username, ''), COALESCE(u.full_name, ''),
		        t.created_by, t.created_at, t.expires_at, t.last_downloaded_at,
		        t.used_at, t.used_hostname, t.revoked_at
		 FROM install_tokens t
		 LEFT JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1
		   AND t.used_at IS NULL
		   AND t.revoked_at IS NULL
		   AND t.expires_at > NOW()
		 LIMIT 1`,
		HashInstallToken(rawToken),
	)
	token, err := scanInstallTokenRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get install token: %w", err)
	}
	return &token, nil
}

func (r *Repository) MarkInstallTokenDownloaded(ctx context.Context, tokenID int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE install_tokens SET last_downloaded_at = NOW() WHERE id = $1 AND last_downloaded_at IS NULL`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("mark install token downloaded: %w", err)
	}
	return nil
}

func (r *Repository) MarkInstallTokenUsed(ctx context.Context, tokenID int64, hostname string, agentID int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE install_tokens
		 SET used_at = COALESCE(used_at, NOW()),
		     used_hostname = COALESCE(NULLIF(used_hostname, ''), $2),
		     used_agent_id = COALESCE(used_agent_id, $3)
		 WHERE id = $1`,
		tokenID, hostname, agentID,
	)
	if err != nil {
		return fmt.Errorf("mark install token used: %w", err)
	}
	return nil
}

func (r *Repository) RevokeInstallToken(ctx context.Context, tokenID int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE install_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("revoke install token: %w", err)
	}
	return nil
}

type installTokenScanner interface {
	Scan(dest ...any) error
}

func scanInstallTokenRow(s installTokenScanner) (InstallTokenRow, error) {
	var row InstallTokenRow
	var userID, createdBy sql.NullInt64
	var lastDownloadedAt, usedAt, revokedAt sql.NullTime
	if err := s.Scan(&row.ID, &userID, &row.Username, &row.FullName,
		&createdBy, &row.CreatedAt, &row.ExpiresAt, &lastDownloadedAt,
		&usedAt, &row.UsedHostname, &revokedAt); err != nil {
		return row, err
	}
	if userID.Valid {
		row.UserID = &userID.Int64
	}
	if createdBy.Valid {
		row.CreatedBy = &createdBy.Int64
	}
	if lastDownloadedAt.Valid {
		t := lastDownloadedAt.Time
		row.LastDownloadedAt = &t
	}
	if usedAt.Valid {
		t := usedAt.Time
		row.UsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		row.RevokedAt = &t
	}
	return row, nil
}
