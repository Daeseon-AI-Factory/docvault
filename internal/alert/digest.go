package alert

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SendDailyDigest builds a plain-Korean 24-hour summary and emails it. No-op if
// email isn't configured. Deterministic (no AI) so it always works and is free.
func (n *Notifier) SendDailyDigest(ctx context.Context, db *pgxpool.Pool, repo *Repository) error {
	if !n.email.enabled() {
		return nil
	}
	subject, body := buildDailyDigest(ctx, db, repo, n.email.PublicURL)
	return sendEmail(n.email, subject, body)
}

func buildDailyDigest(ctx context.Context, db *pgxpool.Pool, repo *Repository, publicURL string) (string, string) {
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		loc = time.Local
	}
	today := time.Now().In(loc).Format("2006-01-02")

	var b strings.Builder
	fmt.Fprintf(&b, "DocVault 일일 보안 요약 (%s)\n", today)
	b.WriteString("====================================\n\n")

	// 1) Last-24h endpoint activity, by type.
	b.WriteString("■ 지난 24시간 활동\n")
	total := 0
	if rows, qErr := db.Query(ctx, `SELECT event_type, COUNT(*) FROM endpoint_events
		WHERE event_time > NOW() - INTERVAL '24 hours' GROUP BY event_type ORDER BY COUNT(*) DESC`); qErr == nil {
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var t string
			var c int
			if rows.Scan(&t, &c) == nil {
				total += c
				lines = append(lines, fmt.Sprintf("  - %s: %d건", t, c))
			}
		}
		fmt.Fprintf(&b, "  전체 이벤트: %d건\n", total)
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		if total == 0 {
			b.WriteString("  (활동 없음)\n")
		}
	} else {
		b.WriteString("  (집계 실패)\n")
	}
	b.WriteString("\n")

	// 2) Unacknowledged alerts (top 10).
	b.WriteString("■ 미확인 알림\n")
	if alerts, aErr := repo.ListAlerts(ctx, true, 10, 0); aErr == nil {
		suffix := ""
		if len(alerts) == 10 {
			suffix = " (상위 10개)"
		}
		fmt.Fprintf(&b, "  미확인 알림: %d건%s\n", len(alerts), suffix)
		for _, a := range alerts {
			fmt.Fprintf(&b, "  - [%s] %s\n", a.Severity, a.Message)
		}
		if len(alerts) == 0 {
			b.WriteString("  (없음 — 깨끗합니다)\n")
		}
	} else {
		b.WriteString("  (조회 실패)\n")
	}
	b.WriteString("\n")

	if publicURL != "" {
		fmt.Fprintf(&b, "자세히 보기: %s/dashboard\n", strings.TrimRight(publicURL, "/"))
	}
	b.WriteString("\n— DocVault 자동 발송 (하루 1회). 위험 알림은 발생 즉시 별도 메일로도 갑니다.\n")

	return "[DocVault] 일일 보안 요약 — " + today, b.String()
}
