package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
		query += fmt.Sprintf(" AND hostname = $%d", argIdx)
		args = append(args, *params.Hostname)
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
	ID          int64
	Hostname    string
	Source      string
	UserID      *int64
	Username    *string
	FullName    *string
	IsActive    bool
	LastCheckin time.Time
	EventCount  int64
}

// TouchAgent records that an agent was just seen. Event posts, osquery config
// polls, and explicit enrolls all count as liveness; otherwise an idle but
// healthy agent can look offline just because there were no suspicious events.
func (r *Repository) TouchAgent(ctx context.Context, hostname, source string) error {
	if hostname == "" || source == "" {
		return nil
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO endpoint_agents (hostname, source, last_checkin, is_active)
		 VALUES ($1, $2, NOW(), true)
		 ON CONFLICT (hostname, source)
		 DO UPDATE SET last_checkin = NOW(), is_active = true`,
		hostname, source,
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
		`SELECT a.id, a.hostname, a.source, a.user_id, u.username, u.full_name, a.is_active, a.last_checkin,
		        COALESCE((SELECT COUNT(*) FROM endpoint_events e
		                  WHERE e.hostname = a.hostname AND e.event_time >= NOW() - INTERVAL '24 hours'), 0) AS cnt
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
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Source, &a.UserID, &a.Username, &a.FullName,
			&a.IsActive, &a.LastCheckin, &a.EventCount); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
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
