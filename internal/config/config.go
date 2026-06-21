package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DBUrl             string
	MasterKey         string
	VaultPath         string
	JWTSecret         string
	ListenAddr        string
	OsqueryPSK        string
	SlackWebhook      string
	AlertEmail        string
	DefaultLang       string
	InstanceLabel     string
	DemoLoginEnabled  bool
	DemoLoginUsername string

	// Email alerts + daily digest (optional; all email features off if SMTPHost empty).
	SMTPHost  string
	SMTPPort  string
	SMTPUser  string
	SMTPPass  string
	SMTPFrom  string
	PublicURL string // e.g. https://docvault.daeseon.ai — used in email links
	DigestHour int   // local (Asia/Seoul) hour to send the daily digest, default 9

	// Optional: enables the AI summary bot + assistant. Disabled if all keys empty.
	// Provider precedence (when AIProvider unset): openai > gemini > anthropic.
	AnthropicAPIKey string
	GeminiAPIKey    string
	OpenAIAPIKey    string
	AIProvider      string // "openai" | "gemini" | "anthropic" (optional override)
	AIModel         string
}

func Load() (*Config, error) {
	cfg := &Config{
		DBUrl:             os.Getenv("DOCVAULT_DB_URL"),
		MasterKey:         os.Getenv("DOCVAULT_MASTER_KEY"),
		VaultPath:         os.Getenv("DOCVAULT_VAULT_PATH"),
		JWTSecret:         os.Getenv("DOCVAULT_JWT_SECRET"),
		ListenAddr:        os.Getenv("DOCVAULT_LISTEN_ADDR"),
		OsqueryPSK:        os.Getenv("DOCVAULT_OSQUERY_PSK"),
		SlackWebhook:      os.Getenv("DOCVAULT_SLACK_WEBHOOK"),
		AlertEmail:        os.Getenv("DOCVAULT_ALERT_EMAIL"),
		DefaultLang:       os.Getenv("DOCVAULT_DEFAULT_LANG"),
		InstanceLabel:     os.Getenv("DOCVAULT_INSTANCE_LABEL"),
		DemoLoginEnabled:  truthyEnv(os.Getenv("DOCVAULT_DEMO_LOGIN_ENABLED")),
		DemoLoginUsername: os.Getenv("DOCVAULT_DEMO_LOGIN_USERNAME"),

		SMTPHost:  os.Getenv("DOCVAULT_SMTP_HOST"),
		SMTPPort:  os.Getenv("DOCVAULT_SMTP_PORT"),
		SMTPUser:  os.Getenv("DOCVAULT_SMTP_USER"),
		SMTPPass:  os.Getenv("DOCVAULT_SMTP_PASS"),
		SMTPFrom:  os.Getenv("DOCVAULT_SMTP_FROM"),
		PublicURL: os.Getenv("DOCVAULT_PUBLIC_URL"),

		AnthropicAPIKey: os.Getenv("DOCVAULT_ANTHROPIC_API_KEY"),
		GeminiAPIKey:    os.Getenv("DOCVAULT_GEMINI_API_KEY"),
		OpenAIAPIKey:    os.Getenv("DOCVAULT_OPENAI_API_KEY"),
		AIProvider:      os.Getenv("DOCVAULT_AI_PROVIDER"),
		AIModel:         os.Getenv("DOCVAULT_AI_MODEL"),
	}

	if cfg.DBUrl == "" {
		return nil, fmt.Errorf("DOCVAULT_DB_URL is required")
	}
	if cfg.MasterKey == "" {
		return nil, fmt.Errorf("DOCVAULT_MASTER_KEY is required")
	}
	if cfg.VaultPath == "" {
		cfg.VaultPath = "/vault"
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("DOCVAULT_JWT_SECRET is required")
	}
	if cfg.OsqueryPSK == "" {
		return nil, fmt.Errorf("DOCVAULT_OSQUERY_PSK is required")
	}
	if err := validateSecrets(cfg); err != nil {
		return nil, err
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.DefaultLang == "" {
		cfg.DefaultLang = "ko"
	}
	if cfg.DefaultLang != "ko" && cfg.DefaultLang != "en" {
		return nil, fmt.Errorf("DOCVAULT_DEFAULT_LANG must be 'ko' or 'en'")
	}
	if cfg.DemoLoginUsername == "" {
		cfg.DemoLoginUsername = "admin"
	}
	if cfg.SMTPPort == "" {
		cfg.SMTPPort = "587"
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = cfg.SMTPUser
	}
	if h, err := strconv.Atoi(os.Getenv("DOCVAULT_DIGEST_HOUR")); err == nil && h >= 0 && h <= 23 {
		cfg.DigestHour = h
	} else {
		cfg.DigestHour = 9
	}

	return cfg, nil
}

func truthyEnv(v string) bool {
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	default:
		return false
	}
}

// exampleSecrets are the placeholder values shipped in .env.example and
// docker-compose.yml. Refusing them at startup prevents accidentally deploying
// with a publicly known master key or signing secret — critical when the server
// is exposed to the internet.
var exampleSecrets = map[string]bool{
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": true, // .env.example master key
	"change-this-to-a-random-string":                                   true, // .env.example JWT secret
	"docvault-jwt-dev-secret-2024":                                     true, // docker-compose JWT secret
	"change-this-pre-shared-key":                                       true, // .env.example PSK
	"dev-psk-for-testing":                                              true, // docker-compose PSK
}

// validateSecrets rejects known placeholder values and enforces minimum lengths
// for the signing secret and agent PSK.
func validateSecrets(cfg *Config) error {
	if exampleSecrets[cfg.MasterKey] {
		return fmt.Errorf("DOCVAULT_MASTER_KEY is set to a known example value; generate a real key with: openssl rand -hex 32")
	}
	if exampleSecrets[cfg.JWTSecret] || len(cfg.JWTSecret) < 16 {
		return fmt.Errorf("DOCVAULT_JWT_SECRET must be a unique value of at least 16 characters")
	}
	if exampleSecrets[cfg.OsqueryPSK] || len(cfg.OsqueryPSK) < 12 {
		return fmt.Errorf("DOCVAULT_OSQUERY_PSK must be a unique value of at least 12 characters")
	}
	return nil
}
