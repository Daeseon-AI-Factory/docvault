package alert

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type AlertRule struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	EventType   string          `json:"event_type"`
	Condition   json.RawMessage `json:"condition"`
	Severity    Severity        `json:"severity"`
	IsActive    bool            `json:"is_active"`
	CreatedBy   int64           `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type Alert struct {
	ID             int64           `json:"id"`
	RuleID         int64           `json:"rule_id"`
	UserID         *int64          `json:"user_id,omitempty"`
	EventID        *int64          `json:"event_id,omitempty"`
	Severity       Severity        `json:"severity"`
	Message        string          `json:"message"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	IsAcknowledged bool            `json:"is_acknowledged"`
	AcknowledgedBy *int64          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}
