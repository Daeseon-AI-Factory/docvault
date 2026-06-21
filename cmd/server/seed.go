package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

func seedAdmin(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	// Check if admin already exists
	var count int
	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE username = 'admin'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check admin user: %w", err)
	}
	if count > 0 {
		logger.Info("admin user already exists, skipping seed")
	} else {
		// Use an operator-supplied password, or generate a strong random one.
		// Never hardcode a default and never log the password.
		adminPassword := os.Getenv("DOCVAULT_ADMIN_PASSWORD")
		generated := false
		if adminPassword == "" {
			pw, err := randomPassword()
			if err != nil {
				return fmt.Errorf("generate admin password: %w", err)
			}
			adminPassword = pw
			generated = true
		}

		hash, err := user.HashPassword(adminPassword)
		if err != nil {
			return fmt.Errorf("hash admin password: %w", err)
		}

		_, err = pool.Exec(ctx,
			`INSERT INTO users (username, email, password_hash, full_name, role, department)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			"admin", "admin@company.local", hash, "System Admin", "admin", "IT",
		)
		if err != nil {
			return fmt.Errorf("insert admin user: %w", err)
		}

		if generated {
			// Printed once to stdout (not the structured log) so the operator
			// can capture it from the seed container output.
			fmt.Printf("\n=== DocVault admin account created ===\n  username: admin\n  password: %s\n  (shown once — save it now and change it after first login)\n\n", adminPassword)
		}
		logger.Info("seeded admin user", "username", "admin")
	}

	// Seed default alert rules
	if err := seedAlertRules(ctx, pool, logger); err != nil {
		return fmt.Errorf("seed alert rules: %w", err)
	}
	if truthy(os.Getenv("DOCVAULT_DEMO_SEED")) {
		if err := seedDemoData(ctx, pool, logger); err != nil {
			return fmt.Errorf("seed demo data: %w", err)
		}
	}

	return nil
}

func truthy(v string) bool {
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	default:
		return false
	}
}

type seedRule struct {
	Name        string
	Description string
	EventType   string
	Condition   string
	Severity    string
}

func seedAlertRules(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	// Get admin user ID for created_by
	var adminID int64
	err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username = 'admin'`).Scan(&adminID)
	if err != nil {
		return fmt.Errorf("find admin user for seeding rules: %w", err)
	}

	rules := []seedRule{
		{
			Name:        "메신저 파일 전송 감지",
			Description: "카카오톡, 텔레그램, 슬랙 등 메신저가 업무 문서(CAD/PDF/Office)에 접근 시 알림",
			EventType:   "messenger_file",
			Condition:   `{"process_group":"messenger"}`,
			Severity:    "high",
		},
		{
			Name:        "이메일 파일 첨부 감지",
			Description: "Outlook, Thunderbird 등 이메일 클라이언트가 업무 문서에 접근 시 알림",
			EventType:   "email_attach",
			Condition:   `{"process_group":"email"}`,
			Severity:    "medium",
		},
		{
			Name:        "확장자 변경 탐지 (위장)",
			Description: "문서 파일의 확장자가 변경됨 — 유출 시도 위장 가능성",
			EventType:   "extension_changed",
			Condition:   `{}`,
			Severity:    "critical",
		},
		{
			Name:        "USB 드라이브 파일 복사",
			Description: "이동식 USB 드라이브에 파일이 복사/생성됨",
			EventType:   "usb_copy",
			Condition:   `{}`,
			Severity:    "high",
		},
		{
			Name:        "USB 장치 연결",
			Description: "이동식 USB 저장장치가 PC에 연결됨",
			EventType:   "usb_mount",
			Condition:   `{}`,
			Severity:    "low",
		},
		{
			Name:        "네트워크 공유 파일 복사",
			Description: "네트워크 공유 폴더(UNC 경로)에 파일이 복사됨",
			EventType:   "netshare_copy",
			Condition:   `{}`,
			Severity:    "medium",
		},
		{
			Name:        "클라우드 업로드 추정",
			Description: "브라우저가 업무 문서에 접근 — Google Drive, Naver 메일 등 클라우드 업로드 추정",
			EventType:   "cloud_upload",
			Condition:   `{"process_group":"browser"}`,
			Severity:    "high",
		},
		{
			Name:        "인쇄 감지",
			Description: "문서 인쇄 작업이 감지됨",
			EventType:   "print_job",
			Condition:   `{}`,
			Severity:    "low",
		},
		{
			Name:        "스크린 캡처 도구 실행",
			Description: "스크린샷/화면 캡처 도구가 실행됨",
			EventType:   "screen_capture",
			Condition:   `{}`,
			Severity:    "medium",
		},
		{
			Name:        "CAD 도면 외부 전송 감지",
			Description: "CAD 파일(.dwg/.dxf/.stp)이 메신저 또는 이메일을 통해 접근됨",
			EventType:   "messenger_file,email_attach",
			Condition:   `{"file_extensions":[".dwg",".dxf",".stp",".step",".igs",".iges"]}`,
			Severity:    "critical",
		},
		{
			Name:        "대용량 클립보드 복사",
			Description: "10KB 이상의 데이터가 클립보드에 복사됨 — 대량 데이터 유출 가능성",
			EventType:   "clipboard_copy",
			Condition:   `{"min_content_size":10240}`,
			Severity:    "medium",
		},
	}

	for _, r := range rules {
		var exists int
		err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM alert_rules WHERE name = $1`, r.Name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check rule %s: %w", r.Name, err)
		}
		if exists > 0 {
			continue
		}

		_, err = pool.Exec(ctx,
			`INSERT INTO alert_rules (name, description, event_type, condition, severity, is_active, created_by)
			 VALUES ($1, $2, $3, $4::jsonb, $5, true, $6)`,
			r.Name, r.Description, r.EventType, r.Condition, r.Severity, adminID,
		)
		if err != nil {
			return fmt.Errorf("insert rule %s: %w", r.Name, err)
		}

		logger.Info("seeded alert rule", "name", r.Name, "severity", r.Severity)
	}

	return nil
}

func seedDemoData(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	password := os.Getenv("DOCVAULT_DEMO_USER_PASSWORD")
	if password == "" {
		password = "demo-user-password-not-for-admin"
	}
	hash, err := user.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash demo user password: %w", err)
	}

	type demoUser struct {
		username   string
		email      string
		fullName   string
		department string
	}
	demoUsers := []demoUser{
		{"alice.kim", "alice.kim@demo.docvault.local", "Alice Kim", "Finance"},
		{"ben.park", "ben.park@demo.docvault.local", "Ben Park", "Engineering"},
		{"maria.choi", "maria.choi@demo.docvault.local", "Maria Choi", "Sales"},
	}

	userIDs := map[string]int64{}
	for _, u := range demoUsers {
		var id int64
		err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, password_hash, full_name, role, department)
			 VALUES ($1, $2, $3, $4, 'employee', $5)
			 ON CONFLICT (username) DO UPDATE
			 SET email = EXCLUDED.email,
			     full_name = EXCLUDED.full_name,
			     department = EXCLUDED.department,
			     updated_at = NOW()
			 RETURNING id`,
			u.username, u.email, hash, u.fullName, u.department,
		).Scan(&id)
		if err != nil {
			return fmt.Errorf("upsert demo user %s: %w", u.username, err)
		}
		userIDs[u.username] = id
	}

	// Demo trial-login user (DOCVAULT_DEMO_LOGIN_USERNAME=demo). Admin role so the
	// demo shows the FULL product (admin screens + AI), identical to a real instance.
	// It's safe because the demo session is read-only: the DemoReadOnly middleware
	// blocks every mutation and the assistant runs on a read-only engine.
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (username, email, password_hash, full_name, role, department)
		 VALUES ('demo', 'demo@demo.docvault.local', $1, 'Demo Admin', 'admin', 'Demo')
		 ON CONFLICT (username) DO UPDATE
		 SET role = 'admin', full_name = EXCLUDED.full_name, is_active = true, updated_at = NOW()`,
		hash,
	); err != nil {
		return fmt.Errorf("upsert demo user: %w", err)
	}

	now := time.Now()
	trueValue := true
	falseValue := false
	type demoAgent struct {
		hostname       string
		source         string
		username       string
		userID         any
		ip             string
		lastCheckin    time.Time
		health         string
		clipboardOK    any
		clipboardError string
		lastSelfTest   any
		lastClipboard  any
		runningMode    string
		sessionUser    string
	}
	agents := []demoAgent{
		{
			hostname: "DEMO-FIN-01", source: "clipboard", username: "DEMO-FIN-01\\alice",
			userID: userIDs["alice.kim"], ip: "10.10.20.14", lastCheckin: now.Add(-2 * time.Minute),
			health: "capture_ok", clipboardOK: trueValue, lastSelfTest: now.Add(-3 * time.Minute),
			lastClipboard: now.Add(-90 * time.Second), runningMode: "interactive_user", sessionUser: "alice",
		},
		{
			hostname: "DEMO-ENG-07", source: "clipboard", username: "DEMO-ENG-07\\ben",
			userID: userIDs["ben.park"], ip: "10.10.30.27", lastCheckin: now.Add(-4 * time.Minute),
			health: "capture_waiting", clipboardOK: trueValue, lastSelfTest: now.Add(-4 * time.Minute),
			runningMode: "interactive_user", sessionUser: "ben",
		},
		{
			hostname: "DEMO-UNASSIGNED-02", source: "clipboard", username: "DEMO-UNASSIGNED-02\\temp",
			userID: nil, ip: "10.10.40.33", lastCheckin: now.Add(-5 * time.Minute),
			health: "capture_waiting", clipboardOK: trueValue, lastSelfTest: now.Add(-5 * time.Minute),
			runningMode: "interactive_user", sessionUser: "temp",
		},
		{
			hostname: "DEMO-SALES-03", source: "clipboard", username: "DEMO-SALES-03\\maria",
			userID: userIDs["maria.choi"], ip: "10.10.50.19", lastCheckin: now.Add(-47 * time.Minute),
			health: "capture_ok", clipboardOK: trueValue, lastSelfTest: now.Add(-48 * time.Minute),
			lastClipboard: now.Add(-49 * time.Minute), runningMode: "interactive_user", sessionUser: "maria",
		},
		{
			hostname: "DEMO-LEGACY-01", source: "clipboard", username: "DEMO-LEGACY-01$",
			userID: userIDs["ben.park"], ip: "10.10.30.91", lastCheckin: now.Add(-8 * time.Minute),
			health: "problem", clipboardOK: falseValue, clipboardError: "Agent is running outside the interactive user session",
			lastSelfTest: now.Add(-8 * time.Minute), runningMode: "windows_service", sessionUser: "LocalSystem",
		},
	}

	for _, a := range agents {
		_, err := pool.Exec(ctx,
			`INSERT INTO endpoint_agents
			   (hostname, source, user_id, reported_username, last_ip, is_active, last_checkin,
			    enrolled_at, agent_version, running_mode, session_username, health_status,
			    clipboard_available, clipboard_error, last_self_test_at, last_clipboard_event_at)
			 VALUES ($1, $2, $3, $4, $5, true, $6, $6, 'demo', $7, $8, $9, $10, $11, $12, $13)
			 ON CONFLICT (hostname, source) DO UPDATE
			 SET user_id = EXCLUDED.user_id,
			     reported_username = EXCLUDED.reported_username,
			     last_ip = EXCLUDED.last_ip,
			     is_active = true,
			     last_checkin = EXCLUDED.last_checkin,
			     agent_version = EXCLUDED.agent_version,
			     running_mode = EXCLUDED.running_mode,
			     session_username = EXCLUDED.session_username,
			     health_status = EXCLUDED.health_status,
			     clipboard_available = EXCLUDED.clipboard_available,
			     clipboard_error = EXCLUDED.clipboard_error,
			     last_self_test_at = EXCLUDED.last_self_test_at,
			     last_clipboard_event_at = EXCLUDED.last_clipboard_event_at`,
			a.hostname, a.source, a.userID, a.username, a.ip, a.lastCheckin,
			a.runningMode, a.sessionUser, a.health, a.clipboardOK, a.clipboardError,
			a.lastSelfTest, a.lastClipboard,
		)
		if err != nil {
			return fmt.Errorf("upsert demo agent %s: %w", a.hostname, err)
		}
	}

	var eventCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_events WHERE hostname LIKE 'DEMO-%'`).Scan(&eventCount); err != nil {
		return fmt.Errorf("count demo events: %w", err)
	}
	if eventCount == 0 {
		type demoEvent struct {
			userID      any
			hostname    string
			eventType   string
			fileName    string
			filePath    string
			processName string
			source      string
			eventTime   time.Time
			detail      string
		}
		events := []demoEvent{
			{userIDs["alice.kim"], "DEMO-FIN-01", "clipboard_copy", "customer-pricing.xlsx", "C:\\Users\\alice\\Documents\\customer-pricing.xlsx", "EXCEL.EXE", "clipboard", now.Add(-90 * time.Second), `{"content_size":18420,"window":"Microsoft Excel"}`},
			{userIDs["ben.park"], "DEMO-ENG-07", "usb_copy", "prototype-v3.step", "E:\\prototype-v3.step", "explorer.exe", "osquery", now.Add(-18 * time.Minute), `{"drive":"E:","device":"USB Mass Storage"}`},
			{userIDs["maria.choi"], "DEMO-SALES-03", "cloud_upload", "partner-contract.pdf", "C:\\Users\\maria\\Downloads\\partner-contract.pdf", "chrome.exe", "osquery", now.Add(-53 * time.Minute), `{"site":"drive.google.com","confidence":"demo"}`},
			{userIDs["ben.park"], "DEMO-LEGACY-01", "screen_capture", "", "", "SnippingTool.exe", "osquery", now.Add(-75 * time.Minute), `{"tool":"Snipping Tool"}`},
			{nil, "DEMO-UNASSIGNED-02", "clipboard_copy", "unknown-text", "", "notepad.exe", "clipboard", now.Add(-2 * time.Hour), `{"content_size":512,"note":"unassigned demo host"}`},
		}
		for _, e := range events {
			_, err := pool.Exec(ctx,
				`INSERT INTO endpoint_events
				   (user_id, hostname, event_type, file_name, file_path, process_name, detail, source, event_time)
				 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
				e.userID, e.hostname, e.eventType, e.fileName, e.filePath, e.processName, e.detail, e.source, e.eventTime,
			)
			if err != nil {
				return fmt.Errorf("insert demo event %s/%s: %w", e.hostname, e.eventType, err)
			}
		}
	}

	var adminID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username = 'admin'`).Scan(&adminID); err != nil {
		return fmt.Errorf("find admin for demo seed: %w", err)
	}
	var ruleID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM alert_rules ORDER BY id LIMIT 1`).Scan(&ruleID); err != nil {
		return fmt.Errorf("find alert rule for demo seed: %w", err)
	}
	alerts := []struct {
		userID   any
		severity string
		message  string
		detail   string
	}{
		{userIDs["alice.kim"], "medium", "Demo: large clipboard copy from customer-pricing.xlsx", `{"hostname":"DEMO-FIN-01","portfolio_demo":true}`},
		{userIDs["ben.park"], "high", "Demo: engineering file copied to removable USB drive", `{"hostname":"DEMO-ENG-07","portfolio_demo":true}`},
		{nil, "medium", "Demo: unassigned PC is reporting activity", `{"hostname":"DEMO-UNASSIGNED-02","portfolio_demo":true}`},
	}
	for _, a := range alerts {
		var exists int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE message = $1`, a.message).Scan(&exists); err != nil {
			return fmt.Errorf("check demo alert: %w", err)
		}
		if exists > 0 {
			continue
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO alerts (rule_id, user_id, severity, message, detail, is_acknowledged, created_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, false, NOW())`,
			ruleID, a.userID, a.severity, a.message, a.detail,
		); err != nil {
			return fmt.Errorf("insert demo alert: %w", err)
		}
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_logs (user_id, action, target_type, target_name, detail, ip_address, user_agent, status_code, created_at)
		 SELECT $1, 'demo_seed', 'portfolio', 'DocVault demo data',
		        '{"portfolio_demo":true}'::jsonb, '127.0.0.1', 'seed', 200, NOW()
		 WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'demo_seed' AND target_name = 'DocVault demo data')`,
		adminID,
	); err != nil {
		return fmt.Errorf("insert demo audit log: %w", err)
	}

	logger.Info("seeded portfolio demo data")
	return nil
}

// randomPassword returns a URL-safe ~24-character random password.
func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
