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

	// 1b) Most active people in the last 24h — WHO, not just what.
	b.WriteString("■ 활동 많은 사람 (지난 24시간)\n")
	if rows, qErr := db.Query(ctx, `SELECT COALESCE(NULLIF(u.full_name,''), u.username, '미배정 PC(' || ee.hostname || ')') AS who, COUNT(*) AS n
		FROM endpoint_events ee LEFT JOIN users u ON ee.user_id = u.id
		WHERE ee.event_time > NOW() - INTERVAL '24 hours'
		GROUP BY who ORDER BY n DESC LIMIT 5`); qErr == nil {
		defer rows.Close()
		n := 0
		for rows.Next() {
			var who string
			var c int
			if rows.Scan(&who, &c) == nil {
				fmt.Fprintf(&b, "  - %s: %d건\n", who, c)
				n++
			}
		}
		if n == 0 {
			b.WriteString("  (활동 없음)\n")
		}
	} else {
		b.WriteString("  (집계 실패)\n")
	}
	b.WriteString("\n")

	// 2) Unacknowledged alerts (top 10), each with the person involved.
	b.WriteString("■ 미확인 알림 (관련자 포함)\n")
	if alerts, aErr := repo.ListAlerts(ctx, true, 10, 0); aErr == nil {
		names := alertUserNames(ctx, db, alerts)
		suffix := ""
		if len(alerts) == 10 {
			suffix = " (상위 10개)"
		}
		fmt.Fprintf(&b, "  미확인 알림: %d건%s\n", len(alerts), suffix)
		for _, a := range alerts {
			who := "미상"
			if a.UserID != nil {
				if nm, ok := names[*a.UserID]; ok && nm != "" {
					who = nm
				}
			}
			fmt.Fprintf(&b, "  - [%s] %s (관련자: %s)\n", a.Severity, a.Message, who)
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

// alertUserNames resolves the user_id of each alert to a display name (full name
// or username) in one query, so the digest can show who is involved.
func alertUserNames(ctx context.Context, db *pgxpool.Pool, alerts []*Alert) map[int64]string {
	res := map[int64]string{}
	var ids []int64
	seen := map[int64]bool{}
	for _, a := range alerts {
		if a.UserID != nil && !seen[*a.UserID] {
			seen[*a.UserID] = true
			ids = append(ids, *a.UserID)
		}
	}
	if len(ids) == 0 {
		return res
	}
	rows, err := db.Query(ctx, `SELECT id, COALESCE(NULLIF(full_name,''), username) FROM users WHERE id = ANY($1)`, ids)
	if err != nil {
		return res
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if rows.Scan(&id, &name) == nil {
			res[id] = name
		}
	}
	return res
}
