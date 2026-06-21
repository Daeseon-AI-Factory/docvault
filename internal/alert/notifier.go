package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Notifier pushes alert notifications via Slack webhook and/or email.
type Notifier struct {
	slackWebhook string
	email        EmailConfig
	httpClient   *http.Client
}

func NewNotifier(slackWebhook string, email EmailConfig) *Notifier {
	return &Notifier{
		slackWebhook: slackWebhook,
		email:        email,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Send fans the alert out to every configured channel. Slack gets every alert;
// email is reserved for high/critical so the inbox isn't flooded (everything
// still appears in-app and in the daily digest).
func (n *Notifier) Send(ctx context.Context, a *Alert, rule *AlertRule) error {
	var firstErr error
	if n.slackWebhook != "" {
		if err := n.sendSlack(ctx, a, rule); err != nil {
			firstErr = err
		}
	}
	if n.email.enabled() && (a.Severity == SeverityHigh || a.Severity == SeverityCritical) {
		if err := n.sendAlertEmail(a, rule); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (n *Notifier) sendAlertEmail(a *Alert, rule *AlertRule) error {
	subject := fmt.Sprintf("[DocVault] ⚠️ 보안 알림: %s", rule.Name)
	var b strings.Builder
	fmt.Fprintf(&b, "심각도: %s\n규칙: %s\n내용: %s\n시간: %s\n",
		a.Severity, rule.Name, a.Message, time.Now().Format("2006-01-02 15:04"))
	if n.email.PublicURL != "" {
		fmt.Fprintf(&b, "\n자세히 보기: %s/dashboard\n", strings.TrimRight(n.email.PublicURL, "/"))
	}
	return sendEmail(n.email, subject, b.String())
}

func (n *Notifier) sendSlack(ctx context.Context, a *Alert, rule *AlertRule) error {
	severityEmoji := map[Severity]string{
		SeverityLow:      ":information_source:",
		SeverityMedium:   ":warning:",
		SeverityHigh:     ":rotating_light:",
		SeverityCritical: ":fire:",
	}

	emoji := severityEmoji[a.Severity]

	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *DocVault Alert* [%s]\n*Rule:* %s\n*Message:* %s",
			emoji, a.Severity, rule.Name, a.Message),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.slackWebhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}
