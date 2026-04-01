package ueba

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AnomalyType identifies the kind of behavioral anomaly detected.
type AnomalyType string

const (
	AnomalyAfterHours     AnomalyType = "after_hours"
	AnomalyWeekendAccess  AnomalyType = "weekend_access"
	AnomalyBulkDownload   AnomalyType = "bulk_download"
	AnomalyNewIP          AnomalyType = "new_ip"
	AnomalyNewHostname    AnomalyType = "new_hostname"
	AnomalyUnusualFile    AnomalyType = "unusual_filetype"
	AnomalyExtDisguise    AnomalyType = "ext_disguise"
	AnomalyBulkClipboard  AnomalyType = "bulk_clipboard"
	AnomalyMessengerLeak  AnomalyType = "messenger_leak"
	AnomalyRapidAccess    AnomalyType = "rapid_access"
)

// Severity levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// AnomalyWeight maps anomaly types to their risk score weight.
var AnomalyWeight = map[AnomalyType]int{
	AnomalyAfterHours:    10,
	AnomalyWeekendAccess: 8,
	AnomalyBulkDownload:  20,
	AnomalyNewIP:         5,
	AnomalyNewHostname:   5,
	AnomalyUnusualFile:   8,
	AnomalyExtDisguise:   30,
	AnomalyBulkClipboard: 15,
	AnomalyMessengerLeak: 25,
	AnomalyRapidAccess:   12,
}

// Analyzer evaluates user behavior against baselines and detects anomalies.
type Analyzer struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

func NewAnalyzer(db *pgxpool.Pool, logger *slog.Logger) *Analyzer {
	return &Analyzer{db: db, logger: logger}
}

// EventContext contains the information needed to evaluate a single event.
type EventContext struct {
	UserID      int64
	EventType   string
	FileName    string
	FilePath    string
	ProcessName string
	Hostname    string
	IPAddress   string
	EventTime   time.Time
}

// Baseline holds the user's normal behavior pattern.
type Baseline struct {
	AvgDailyEvents    float64
	AvgDailyDownloads float64
	TypicalStartHour  int
	TypicalEndHour    int
	WorksWeekends     bool
	KnownIPs          []string
	KnownHostnames    []string
	FrequentFileTypes []string
}

// RiskFactor is a single contributing factor to a user's risk score.
type RiskFactor struct {
	Factor  string `json:"factor"`
	Weight  int    `json:"weight"`
	Detail  string `json:"detail"`
}

// AnalyzeEvent checks a single event against the user's baseline and records any anomalies.
func (a *Analyzer) AnalyzeEvent(ctx context.Context, evt EventContext) []RiskFactor {
	if evt.UserID == 0 {
		return nil
	}

	baseline := a.loadBaseline(ctx, evt.UserID)
	var factors []RiskFactor

	// 1. After-hours access
	hour := evt.EventTime.Hour()
	if hour < baseline.TypicalStartHour || hour > baseline.TypicalEndHour {
		f := RiskFactor{
			Factor: string(AnomalyAfterHours),
			Weight: AnomalyWeight[AnomalyAfterHours],
			Detail: fmt.Sprintf("Activity at %02d:%02d (typical: %02d:00-%02d:00)",
				hour, evt.EventTime.Minute(), baseline.TypicalStartHour, baseline.TypicalEndHour),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyAfterHours, SeverityMedium, f.Detail)
	}

	// 2. Weekend access
	weekday := evt.EventTime.Weekday()
	if (weekday == time.Saturday || weekday == time.Sunday) && !baseline.WorksWeekends {
		f := RiskFactor{
			Factor: string(AnomalyWeekendAccess),
			Weight: AnomalyWeight[AnomalyWeekendAccess],
			Detail: fmt.Sprintf("Activity on %s", weekday),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyWeekendAccess, SeverityMedium, f.Detail)
	}

	// 3. New IP address
	if evt.IPAddress != "" && !contains(baseline.KnownIPs, evt.IPAddress) {
		f := RiskFactor{
			Factor: string(AnomalyNewIP),
			Weight: AnomalyWeight[AnomalyNewIP],
			Detail: fmt.Sprintf("New IP: %s", evt.IPAddress),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyNewIP, SeverityLow, f.Detail)
	}

	// 4. New hostname
	if evt.Hostname != "" && !contains(baseline.KnownHostnames, evt.Hostname) {
		f := RiskFactor{
			Factor: string(AnomalyNewHostname),
			Weight: AnomalyWeight[AnomalyNewHostname],
			Detail: fmt.Sprintf("New hostname: %s", evt.Hostname),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyNewHostname, SeverityLow, f.Detail)
	}

	// 5. Extension disguise
	if evt.EventType == "ext_changed" {
		f := RiskFactor{
			Factor: string(AnomalyExtDisguise),
			Weight: AnomalyWeight[AnomalyExtDisguise],
			Detail: fmt.Sprintf("Extension disguise: %s", evt.FileName),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyExtDisguise, SeverityCritical, f.Detail)
	}

	// 6. Messenger file leak
	if evt.EventType == "messenger_file" || evt.EventType == "email_attach" {
		sev := SeverityHigh
		f := RiskFactor{
			Factor: string(AnomalyMessengerLeak),
			Weight: AnomalyWeight[AnomalyMessengerLeak],
			Detail: fmt.Sprintf("%s via %s: %s", evt.EventType, evt.ProcessName, evt.FileName),
		}
		factors = append(factors, f)
		a.recordAnomaly(ctx, evt.UserID, AnomalyMessengerLeak, sev, f.Detail)
	}

	// 7. Unusual file type access
	if evt.FileName != "" {
		ext := strings.ToLower(fileExt(evt.FileName))
		if ext != "" && len(baseline.FrequentFileTypes) > 0 && !contains(baseline.FrequentFileTypes, ext) {
			f := RiskFactor{
				Factor: string(AnomalyUnusualFile),
				Weight: AnomalyWeight[AnomalyUnusualFile],
				Detail: fmt.Sprintf("Uncommon file type: %s (%s)", ext, evt.FileName),
			}
			factors = append(factors, f)
			a.recordAnomaly(ctx, evt.UserID, AnomalyUnusualFile, SeverityLow, f.Detail)
		}
	}

	// 8. Bulk download check (count today's downloads)
	if evt.EventType == "file.download" || evt.EventType == "file_write" || evt.EventType == "usb_copy" {
		todayCount := a.countTodayEvents(ctx, evt.UserID, evt.EventTime)
		threshold := int(baseline.AvgDailyEvents * 2)
		if threshold < 20 {
			threshold = 20
		}
		if todayCount > threshold {
			f := RiskFactor{
				Factor: string(AnomalyBulkDownload),
				Weight: AnomalyWeight[AnomalyBulkDownload],
				Detail: fmt.Sprintf("%d events today (avg: %.0f, threshold: %d)", todayCount, baseline.AvgDailyEvents, threshold),
			}
			factors = append(factors, f)
			a.recordAnomaly(ctx, evt.UserID, AnomalyBulkDownload, SeverityHigh, f.Detail)
		}
	}

	// Update risk score if any anomalies detected
	if len(factors) > 0 {
		a.updateRiskScore(ctx, evt.UserID, factors)
	}

	return factors
}

func (a *Analyzer) loadBaseline(ctx context.Context, userID int64) Baseline {
	b := Baseline{
		AvgDailyEvents:   10,
		TypicalStartHour: 8,
		TypicalEndHour:   19,
	}

	row := a.db.QueryRow(ctx,
		`SELECT avg_daily_events, avg_daily_downloads, typical_start_hour, typical_end_hour,
		        works_weekends, known_ips, known_hostnames, frequent_file_types
		 FROM user_behavior_baselines WHERE user_id = $1`, userID)

	var knownIPs, knownHostnames, freqTypes []string
	err := row.Scan(&b.AvgDailyEvents, &b.AvgDailyDownloads, &b.TypicalStartHour, &b.TypicalEndHour,
		&b.WorksWeekends, &knownIPs, &knownHostnames, &freqTypes)
	if err == nil {
		b.KnownIPs = knownIPs
		b.KnownHostnames = knownHostnames
		b.FrequentFileTypes = freqTypes
	}

	return b
}

func (a *Analyzer) recordAnomaly(ctx context.Context, userID int64, anomalyType AnomalyType, severity, detail string) {
	_, err := a.db.Exec(ctx,
		`INSERT INTO anomaly_events (user_id, anomaly_type, severity, detail)
		 VALUES ($1, $2, $3, $4)`, userID, anomalyType, severity, detail)
	if err != nil {
		a.logger.Error("record anomaly", "error", err, "user_id", userID, "type", anomalyType)
	}
}

func (a *Analyzer) updateRiskScore(ctx context.Context, userID int64, factors []RiskFactor) {
	totalScore := 0
	for _, f := range factors {
		totalScore += f.Weight
	}
	if totalScore > 100 {
		totalScore = 100
	}

	factorsJSON, _ := json.Marshal(factors)

	_, err := a.db.Exec(ctx,
		`INSERT INTO risk_scores (user_id, score, factors, scored_at)
		 VALUES ($1, $2, $3, CURRENT_DATE)
		 ON CONFLICT (user_id, scored_at) DO UPDATE
		 SET score = LEAST(risk_scores.score + $2, 100),
		     factors = risk_scores.factors || $3::jsonb`,
		userID, totalScore, factorsJSON)
	if err != nil {
		a.logger.Error("update risk score", "error", err, "user_id", userID)
	}
}

func (a *Analyzer) countTodayEvents(ctx context.Context, userID int64, t time.Time) int {
	startOfDay := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	var count int
	a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM endpoint_events WHERE user_id = $1 AND event_time >= $2`,
		userID, startOfDay).Scan(&count)
	return count
}

// RecalculateBaselines updates all user behavior baselines from the last 30 days of data.
func (a *Analyzer) RecalculateBaselines(ctx context.Context) error {
	_, err := a.db.Exec(ctx, `
		INSERT INTO user_behavior_baselines (user_id, avg_daily_events, avg_daily_downloads,
			typical_start_hour, typical_end_hour, works_weekends,
			known_ips, known_hostnames, frequent_file_types, calculated_at)
		SELECT
			u.id,
			COALESCE(e.avg_events, 0),
			COALESCE(d.avg_downloads, 0),
			COALESCE(h.start_hour, 8),
			COALESCE(h.end_hour, 19),
			COALESCE(w.works_weekends, false),
			COALESCE(ips.known_ips, ARRAY[]::TEXT[]),
			COALESCE(hosts.known_hostnames, ARRAY[]::TEXT[]),
			COALESCE(ft.frequent_types, ARRAY[]::TEXT[]),
			NOW()
		FROM users u
		LEFT JOIN LATERAL (
			SELECT (COUNT(*)::REAL / GREATEST(1, DATE_PART('day', NOW() - MIN(event_time)))) as avg_events
			FROM endpoint_events WHERE user_id = u.id AND event_time >= NOW() - INTERVAL '30 days'
		) e ON true
		LEFT JOIN LATERAL (
			SELECT (COUNT(*)::REAL / GREATEST(1, DATE_PART('day', NOW() - MIN(created_at)))) as avg_downloads
			FROM audit_logs WHERE user_id = u.id AND action = 'file.download' AND created_at >= NOW() - INTERVAL '30 days'
		) d ON true
		LEFT JOIN LATERAL (
			SELECT MIN(EXTRACT(HOUR FROM event_time))::SMALLINT as start_hour,
			       MAX(EXTRACT(HOUR FROM event_time))::SMALLINT as end_hour
			FROM endpoint_events
			WHERE user_id = u.id AND event_time >= NOW() - INTERVAL '30 days'
			  AND EXTRACT(DOW FROM event_time) BETWEEN 1 AND 5
		) h ON true
		LEFT JOIN LATERAL (
			SELECT COUNT(*) > 5 as works_weekends
			FROM endpoint_events
			WHERE user_id = u.id AND event_time >= NOW() - INTERVAL '30 days'
			  AND EXTRACT(DOW FROM event_time) IN (0, 6)
		) w ON true
		LEFT JOIN LATERAL (
			SELECT ARRAY_AGG(DISTINCT ip_address) as known_ips
			FROM audit_logs WHERE user_id = u.id AND created_at >= NOW() - INTERVAL '30 days' AND ip_address != ''
		) ips ON true
		LEFT JOIN LATERAL (
			SELECT ARRAY_AGG(DISTINCT hostname) as known_hostnames
			FROM endpoint_events WHERE user_id = u.id AND event_time >= NOW() - INTERVAL '30 days' AND hostname != ''
		) hosts ON true
		LEFT JOIN LATERAL (
			SELECT ARRAY_AGG(DISTINCT ext) as frequent_types FROM (
				SELECT LOWER(SUBSTRING(file_name FROM '\.([^.]+)$')) as ext
				FROM endpoint_events WHERE user_id = u.id AND event_time >= NOW() - INTERVAL '30 days'
				  AND file_name != '' GROUP BY 1 HAVING COUNT(*) >= 3
			) sub
		) ft ON true
		WHERE u.is_active = true
		ON CONFLICT (user_id) DO UPDATE SET
			avg_daily_events = EXCLUDED.avg_daily_events,
			avg_daily_downloads = EXCLUDED.avg_daily_downloads,
			typical_start_hour = EXCLUDED.typical_start_hour,
			typical_end_hour = EXCLUDED.typical_end_hour,
			works_weekends = EXCLUDED.works_weekends,
			known_ips = EXCLUDED.known_ips,
			known_hostnames = EXCLUDED.known_hostnames,
			frequent_file_types = EXCLUDED.frequent_file_types,
			calculated_at = NOW()
	`)
	if err != nil {
		return fmt.Errorf("recalculate baselines: %w", err)
	}
	a.logger.Info("recalculated user behavior baselines")
	return nil
}

// GetTopRiskUsers returns the top N users by today's risk score.
func (a *Analyzer) GetTopRiskUsers(ctx context.Context, limit int) ([]UserRiskSummary, error) {
	rows, err := a.db.Query(ctx,
		`SELECT r.user_id, u.username, u.full_name, r.score, r.factors
		 FROM risk_scores r
		 JOIN users u ON r.user_id = u.id
		 WHERE r.scored_at = CURRENT_DATE AND r.score > 0
		 ORDER BY r.score DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("get top risk users: %w", err)
	}
	defer rows.Close()

	var results []UserRiskSummary
	for rows.Next() {
		var s UserRiskSummary
		var factorsJSON []byte
		if err := rows.Scan(&s.UserID, &s.Username, &s.FullName, &s.Score, &factorsJSON); err != nil {
			continue
		}
		json.Unmarshal(factorsJSON, &s.Factors)
		s.Level = scoreToLevel(s.Score)
		results = append(results, s)
	}
	return results, nil
}

// UserRiskSummary is displayed on the dashboard.
type UserRiskSummary struct {
	UserID   int64        `json:"user_id"`
	Username string       `json:"username"`
	FullName string       `json:"full_name"`
	Score    int          `json:"score"`
	Level    string       `json:"level"` // "low", "medium", "high", "critical"
	Factors  []RiskFactor `json:"factors"`
}

func scoreToLevel(score int) string {
	switch {
	case score >= 70:
		return SeverityCritical
	case score >= 40:
		return SeverityHigh
	case score >= 20:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func fileExt(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[i:]
}
