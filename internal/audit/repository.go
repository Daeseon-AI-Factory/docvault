package audit

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

func (r *Repository) Log(ctx context.Context, e Entry) error {
	var detail []byte
	if e.Detail != nil {
		var err error
		detail, err = json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO audit_logs (user_id, action, target_type, target_id, target_name, detail, ip_address, user_agent, status_code)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.UserID, e.Action, e.TargetType, e.TargetID, e.TargetName, detail, e.IPAddress, e.UserAgent, e.StatusCode,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

type SearchParams struct {
	UserID     *int64
	Action     *Action
	TargetType *string
	TargetID   *int64
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

func (r *Repository) Search(ctx context.Context, params SearchParams) ([]*AuditLog, error) {
	query := `SELECT id, user_id, action, target_type, target_id, target_name, detail, ip_address, user_agent, status_code, created_at
	          FROM audit_logs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if params.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, *params.UserID)
		argIdx++
	}
	if params.Action != nil {
		query += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, *params.Action)
		argIdx++
	}
	if params.TargetType != nil {
		query += fmt.Sprintf(" AND target_type = $%d", argIdx)
		args = append(args, *params.TargetType)
		argIdx++
	}
	if params.TargetID != nil {
		query += fmt.Sprintf(" AND target_id = $%d", argIdx)
		args = append(args, *params.TargetID)
		argIdx++
	}
	if params.From != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, *params.From)
		argIdx++
	}
	if params.To != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argIdx)
		args = append(args, *params.To)
		argIdx++
	}

	query += " ORDER BY created_at DESC"

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
		return nil, fmt.Errorf("search audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.TargetType, &l.TargetID, &l.TargetName,
			&l.Detail, &l.IPAddress, &l.UserAgent, &l.StatusCode, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, &l)
	}
	return logs, rows.Err()
}

type DashboardStats struct {
	TotalEvents   int64            `json:"total_events"`
	TodayEvents   int64            `json:"today_events"`
	ActionCounts  map[string]int64 `json:"action_counts"`
}

func (r *Repository) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{ActionCounts: make(map[string]int64)}

	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, fmt.Errorf("count total events: %w", err)
	}

	err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE created_at >= CURRENT_DATE`).Scan(&stats.TodayEvents)
	if err != nil {
		return nil, fmt.Errorf("count today events: %w", err)
	}

	rows, err := r.db.Query(ctx,
		`SELECT action, COUNT(*) FROM audit_logs WHERE created_at >= CURRENT_DATE GROUP BY action ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, fmt.Errorf("count actions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var action string
		var count int64
		if err := rows.Scan(&action, &count); err != nil {
			return nil, fmt.Errorf("scan action count: %w", err)
		}
		stats.ActionCounts[action] = count
	}

	return stats, rows.Err()
}
