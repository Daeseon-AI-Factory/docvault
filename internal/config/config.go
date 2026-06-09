package config

import (
	"fmt"
	"os"
)

type Config struct {
	DBUrl        string
	MasterKey    string
	VaultPath    string
	JWTSecret    string
	ListenAddr   string
	OsqueryPSK   string
	SlackWebhook string
	AlertEmail   string
}

func Load() (*Config, error) {
	cfg := &Config{
		DBUrl:        os.Getenv("DOCVAULT_DB_URL"),
		MasterKey:    os.Getenv("DOCVAULT_MASTER_KEY"),
		VaultPath:    os.Getenv("DOCVAULT_VAULT_PATH"),
		JWTSecret:    os.Getenv("DOCVAULT_JWT_SECRET"),
		ListenAddr:   os.Getenv("DOCVAULT_LISTEN_ADDR"),
		OsqueryPSK:   os.Getenv("DOCVAULT_OSQUERY_PSK"),
		SlackWebhook: os.Getenv("DOCVAULT_SLACK_WEBHOOK"),
		AlertEmail:   os.Getenv("DOCVAULT_ALERT_EMAIL"),
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
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}

	return cfg, nil
}
