package alert

import (
	"mime"
	"net/smtp"
	"strings"
)

// EmailConfig holds SMTP settings for alert emails + the daily digest.
// All email features are off unless Host, From, and To are set.
type EmailConfig struct {
	Host      string
	Port      string
	User      string
	Pass      string
	From      string
	To        string // recipient (DOCVAULT_ALERT_EMAIL)
	PublicURL string // e.g. https://docvault.daeseon.ai — for links in the email
}

func (c EmailConfig) enabled() bool {
	return c.Host != "" && c.From != "" && c.To != ""
}

// sendEmail sends a UTF-8 plain-text email via SMTP. Uses the stdlib net/smtp,
// which negotiates STARTTLS on the standard submission port (587) — works with
// Gmail/most providers using an app password. No external dependency.
func sendEmail(cfg EmailConfig, subject, body string) error {
	if !cfg.enabled() {
		return nil
	}
	addr := cfg.Host + ":" + cfg.Port
	msg := strings.Join([]string{
		"From: " + cfg.From,
		"To: " + cfg.To,
		"Subject: " + mime.QEncoding.Encode("UTF-8", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	var auth smtp.Auth
	if cfg.User != "" {
		auth = smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	}
	return smtp.SendMail(addr, auth, cfg.From, []string{cfg.To}, []byte(msg))
}
