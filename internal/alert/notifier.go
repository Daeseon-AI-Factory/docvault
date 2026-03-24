package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier sends alert notifications via Slack webhook.
type Notifier struct {
	slackWebhook string
	httpClient   *http.Client
}

func NewNotifier(slackWebhook string) *Notifier {
	return &Notifier{
		slackWebhook: slackWebhook,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *Notifier) Send(ctx context.Context, a *Alert, rule *AlertRule) error {
	if n.slackWebhook == "" {
		return nil // no webhook configured
	}

	return n.sendSlack(ctx, a, rule)
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
