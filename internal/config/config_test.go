package config

import (
	"os"
	"testing"
)

func TestLoadRequiredFields(t *testing.T) {
	// Clear all env vars
	os.Unsetenv("DOCVAULT_DB_URL")
	os.Unsetenv("DOCVAULT_MASTER_KEY")
	os.Unsetenv("DOCVAULT_JWT_SECRET")

	_, err := Load()
	if err == nil {
		t.Error("should fail when DOCVAULT_DB_URL is missing")
	}

	os.Setenv("DOCVAULT_DB_URL", "postgres://localhost/test")
	_, err = Load()
	if err == nil {
		t.Error("should fail when DOCVAULT_MASTER_KEY is missing")
	}

	os.Setenv("DOCVAULT_MASTER_KEY", "testkey")
	_, err = Load()
	if err == nil {
		t.Error("should fail when DOCVAULT_JWT_SECRET is missing")
	}

	os.Setenv("DOCVAULT_JWT_SECRET", "testsecret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("should succeed with all required fields: %v", err)
	}

	if cfg.DBUrl != "postgres://localhost/test" {
		t.Errorf("DBUrl = %s", cfg.DBUrl)
	}
}

func TestLoadDefaults(t *testing.T) {
	os.Setenv("DOCVAULT_DB_URL", "postgres://localhost/test")
	os.Setenv("DOCVAULT_MASTER_KEY", "testkey")
	os.Setenv("DOCVAULT_JWT_SECRET", "testsecret")
	os.Unsetenv("DOCVAULT_LISTEN_ADDR")
	os.Unsetenv("DOCVAULT_VAULT_PATH")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("default ListenAddr = %s, want :8080", cfg.ListenAddr)
	}
	if cfg.VaultPath != "/vault" {
		t.Errorf("default VaultPath = %s, want /vault", cfg.VaultPath)
	}
}
