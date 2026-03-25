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
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
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
	EventType string         `json:"event_type"`
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
