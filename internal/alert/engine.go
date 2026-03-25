package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/endpoint"
)

// RuleCondition defines what triggers an alert.
type RuleCondition struct {
	FileNameContains string   `json:"file_name_contains,omitempty"` // substring match on file name
	FileExtensions   []string `json:"file_extensions,omitempty"`    // match specific extensions (e.g. [".dwg",".pdf"])
	ProcessName      string   `json:"process_name,omitempty"`       // exact match on process name
	ProcessGroup     string   `json:"process_group,omitempty"`      // "messenger", "email", "browser"
	PathContains     string   `json:"path_contains,omitempty"`      // substring match on file path
	MinContentSize   int      `json:"min_content_size,omitempty"`   // for clipboard: minimum bytes
	MinCount         int      `json:"min_count,omitempty"`          // future: threshold-based alerting
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
			"file_path":    event.FilePath,
			"process_name": event.ProcessName,
			"event_type":   event.EventType,
		})

		alert := &Alert{
			RuleID:   rule.ID,
			UserID:   event.UserID,
			EventID:  &event.ID,
			Severity: rule.Severity,
			Message:  fmt.Sprintf("[%s] %s: %s (%s) on %s", rule.Severity, rule.Name, event.FileName, event.EventType, event.Hostname),
			Detail:   detail,
		}

		if err := e.repo.CreateAlert(ctx, alert); err != nil {
			e.logger.Error("alert engine: create alert", "error", err, "rule_id", rule.ID)
			continue
		}

		e.logger.Warn("alert fired",
			"rule", rule.Name,
			"severity", rule.Severity,
			"host", event.Hostname,
			"file", event.FileName,
			"process", event.ProcessName,
		)

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
	// Support comma-separated event types in a single rule
	for _, rt := range strings.Split(ruleType, ",") {
		if strings.EqualFold(strings.TrimSpace(rt), eventType) {
			return true
		}
	}
	return false
}

func matchesCondition(cond *RuleCondition, event *endpoint.EndpointEvent) bool {
	if cond.FileNameContains != "" {
		if !strings.Contains(strings.ToLower(event.FileName), strings.ToLower(cond.FileNameContains)) {
			return false
		}
	}

	if len(cond.FileExtensions) > 0 {
		ext := strings.ToLower(filepath.Ext(event.FileName))
		matched := false
		for _, e := range cond.FileExtensions {
			if strings.ToLower(e) == ext {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if cond.ProcessName != "" {
		if !strings.EqualFold(event.ProcessName, cond.ProcessName) {
			return false
		}
	}

	if cond.ProcessGroup != "" {
		if !matchesProcessGroup(cond.ProcessGroup, event.ProcessName) {
			return false
		}
	}

	if cond.PathContains != "" {
		if !strings.Contains(strings.ToLower(event.FilePath), strings.ToLower(cond.PathContains)) {
			return false
		}
	}

	// Check content size for clipboard events
	if cond.MinContentSize > 0 && event.Detail != nil {
		var detail map[string]interface{}
		if err := json.Unmarshal(event.Detail, &detail); err == nil {
			if size, ok := detail["content_size"].(float64); ok {
				if int(size) < cond.MinContentSize {
					return false
				}
			}
		}
	}

	return true
}

// matchesProcessGroup checks if a process belongs to a named group.
func matchesProcessGroup(group, processName string) bool {
	pLower := strings.ToLower(processName)
	switch strings.ToLower(group) {
	case "messenger":
		_, ok := endpoint.IsMessengerProcess(pLower)
		return ok
	case "email":
		_, ok := endpoint.IsEmailProcess(pLower)
		return ok
	case "browser":
		browsers := []string{"chrome.exe", "msedge.exe", "firefox.exe", "whale.exe", "brave.exe", "iexplore.exe"}
		for _, b := range browsers {
			if pLower == b {
				return true
			}
		}
		return false
	default:
		return false
	}
}
