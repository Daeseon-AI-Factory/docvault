package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
)

// RuleCondition defines what triggers an alert.
type RuleCondition struct {
	FileNameContains string `json:"file_name_contains,omitempty"`
	ProcessName      string `json:"process_name,omitempty"`
	MinCount         int    `json:"min_count,omitempty"` // future: threshold-based alerting
}

// Engine evaluates incoming events against active alert rules.
type Engine struct {
	repo     *Repository
	notifier *Notifier
	logger   *slog.Logger
}

func NewEngine(repo *Repository, notifier *Notifier, logger *slog.Logger) *Engine {
	return &Engine{repo: repo, notifier: notifier, logger: logger}
}

// Evaluate checks an endpoint event against all active rules and fires alerts.
func (e *Engine) Evaluate(ctx context.Context, event *endpoint.EndpointEvent) {
	rules, err := e.repo.ListRules(ctx, true)
	if err != nil {
		e.logger.Error("alert engine: list rules", "error", err)
		return
	}

	for _, rule := range rules {
		if !matchesEventType(rule.EventType, string(event.EventType)) {
			continue
		}

		var cond RuleCondition
		if err := json.Unmarshal(rule.Condition, &cond); err != nil {
			e.logger.Error("alert engine: parse condition", "error", err, "rule_id", rule.ID)
			continue
		}

		if !matchesCondition(&cond, event) {
			continue
		}

		// Fire alert
		detail, _ := json.Marshal(map[string]interface{}{
			"event_id":     event.ID,
			"hostname":     event.Hostname,
			"file_name":    event.FileName,
			"process_name": event.ProcessName,
		})

		alert := &Alert{
			RuleID:   rule.ID,
			UserID:   event.UserID,
			EventID:  &event.ID,
			Severity: rule.Severity,
			Message:  fmt.Sprintf("Rule '%s' triggered: %s on %s", rule.Name, event.EventType, event.Hostname),
			Detail:   detail,
		}

		if err := e.repo.CreateAlert(ctx, alert); err != nil {
			e.logger.Error("alert engine: create alert", "error", err, "rule_id", rule.ID)
			continue
		}

		e.logger.Warn("alert fired", "rule", rule.Name, "severity", rule.Severity, "host", event.Hostname)

		// Send notification
		if e.notifier != nil {
			if err := e.notifier.Send(ctx, alert, rule); err != nil {
				e.logger.Error("alert engine: send notification", "error", err)
			}
		}
	}
}

func matchesEventType(ruleType, eventType string) bool {
	if ruleType == "*" {
		return true
	}
	return strings.EqualFold(ruleType, eventType)
}

func matchesCondition(cond *RuleCondition, event *endpoint.EndpointEvent) bool {
	if cond.FileNameContains != "" {
		if !strings.Contains(strings.ToLower(event.FileName), strings.ToLower(cond.FileNameContains)) {
			return false
		}
	}
	if cond.ProcessName != "" {
		if !strings.EqualFold(event.ProcessName, cond.ProcessName) {
			return false
		}
	}
	return true
}
