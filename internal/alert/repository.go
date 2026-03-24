package alert

import (
	"context"
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

func (r *Repository) CreateRule(ctx context.Context, rule *AlertRule) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO alert_rules (name, description, event_type, condition, severity, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, is_active, created_at, updated_at`,
		rule.Name, rule.Description, rule.EventType, rule.Condition, rule.Severity, rule.CreatedBy,
	).Scan(&rule.ID, &rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert alert rule: %w", err)
	}
	return nil
}

func (r *Repository) ListRules(ctx context.Context, activeOnly bool) ([]*AlertRule, error) {
	query := `SELECT id, name, description, event_type, condition, severity, is_active, created_by, created_at, updated_at
	          FROM alert_rules`
	if activeOnly {
		query += ` WHERE is_active = true`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list alert rules: %w", err)
	}
	defer rows.Close()

	var rules []*AlertRule
	for rows.Next() {
		var rule AlertRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.EventType, &rule.Condition,
			&rule.Severity, &rule.IsActive, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alert rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	return rules, rows.Err()
}

func (r *Repository) CreateAlert(ctx context.Context, a *Alert) error {
	err := r.db.QueryRow(ctx,
		`INSERT INTO alerts (rule_id, user_id, event_id, severity, message, detail)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, created_at`,
		a.RuleID, a.UserID, a.EventID, a.Severity, a.Message, a.Detail,
	).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert alert: %w", err)
	}
	return nil
}

func (r *Repository) ListAlerts(ctx context.Context, unackedOnly bool, limit, offset int) ([]*Alert, error) {
	query := `SELECT id, rule_id, user_id, event_id, severity, message, detail,
	                 is_acknowledged, acknowledged_by, acknowledged_at, created_at
	          FROM alerts`
	args := []interface{}{}
	argIdx := 1

	if unackedOnly {
		query += ` WHERE is_acknowledged = false`
	}
	query += ` ORDER BY created_at DESC`

	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(` LIMIT $%d`, argIdx)
	args = append(args, limit)
	argIdx++

	if offset > 0 {
		query += fmt.Sprintf(` OFFSET $%d`, argIdx)
		args = append(args, offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.RuleID, &a.UserID, &a.EventID, &a.Severity, &a.Message,
			&a.Detail, &a.IsAcknowledged, &a.AcknowledgedBy, &a.AcknowledgedAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		alerts = append(alerts, &a)
	}
	return alerts, rows.Err()
}

func (r *Repository) Acknowledge(ctx context.Context, alertID, userID int64) error {
	now := time.Now()
	result, err := r.db.Exec(ctx,
		`UPDATE alerts SET is_acknowledged = true, acknowledged_by = $1, acknowledged_at = $2
		 WHERE id = $3 AND is_acknowledged = false`,
		userID, now, alertID,
	)
	if err != nil {
		return fmt.Errorf("acknowledge alert %d: %w", alertID, err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("alert %d not found or already acknowledged", alertID)
	}
	return nil
}
