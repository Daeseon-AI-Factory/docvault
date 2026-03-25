package main

import (
	"context"
	"fmt"
	"log/slog"

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
		hash, err := user.HashPassword("admin1234!")
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

		logger.Info("seeded admin user (username: admin, password: admin1234!)")
	}

	// Seed default alert rules
	if err := seedAlertRules(ctx, pool, logger); err != nil {
		return fmt.Errorf("seed alert rules: %w", err)
	}

	return nil
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
