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
	os.Unsetenv("DOCVAULT_OSQUERY_PSK")

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

	os.Setenv("DOCVAULT_JWT_SECRET", "a-strong-test-jwt-secret-123456")
	_, err = Load()
	if err == nil {
		t.Error("should fail when DOCVAULT_OSQUERY_PSK is missing")
	}

	os.Setenv("DOCVAULT_OSQUERY_PSK", "a-strong-test-psk-123456")
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
	os.Setenv("DOCVAULT_JWT_SECRET", "a-strong-test-jwt-secret-123456")
	os.Setenv("DOCVAULT_OSQUERY_PSK", "a-strong-test-psk-123456")
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

func TestLoadRejectsWeakSecrets(t *testing.T) {
	base := func() {
		os.Setenv("DOCVAULT_DB_URL", "postgres://localhost/test")
		os.Setenv("DOCVAULT_MASTER_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
		os.Setenv("DOCVAULT_JWT_SECRET", "a-strong-test-jwt-secret-123456")
		os.Setenv("DOCVAULT_OSQUERY_PSK", "a-strong-test-psk-123456")
	}

	// Known example master key from .env.example must be rejected.
	base()
	os.Setenv("DOCVAULT_MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if _, err := Load(); err == nil {
		t.Error("should reject the example master key")
	}

	// Too-short JWT secret must be rejected.
	base()
	os.Setenv("DOCVAULT_JWT_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Error("should reject a JWT secret shorter than 16 chars")
	}

	// Too-short PSK must be rejected.
	base()
	os.Setenv("DOCVAULT_OSQUERY_PSK", "short")
	if _, err := Load(); err == nil {
		t.Error("should reject a PSK shorter than 12 chars")
	}

	// All-strong values must pass.
	base()
	if _, err := Load(); err != nil {
		t.Errorf("strong secrets should pass: %v", err)
	}
}
