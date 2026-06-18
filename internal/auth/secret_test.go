package auth

import (
	"strings"
	"testing"
)

const testMasterKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestSecretProtectorRoundTrip(t *testing.T) {
	protector, err := NewSecretProtector(testMasterKeyHex)
	if err != nil {
		t.Fatalf("NewSecretProtector: %v", err)
	}

	sealed, err := protector.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(sealed, protectedSecretPrefix) {
		t.Fatalf("sealed secret missing prefix: %q", sealed)
	}
	if sealed == "JBSWY3DPEHPK3PXP" {
		t.Fatal("secret was not encrypted")
	}
	if len(sealed) <= 64 {
		t.Fatalf("sealed secret length = %d, want longer than legacy VARCHAR(64)", len(sealed))
	}

	opened, err := protector.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("opened = %q", opened)
	}
}

func TestSecretProtectorKeepsLegacyPlaintextReadable(t *testing.T) {
	protector, err := NewSecretProtector(testMasterKeyHex)
	if err != nil {
		t.Fatalf("NewSecretProtector: %v", err)
	}
	opened, err := protector.Open("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	if opened != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("opened legacy = %q", opened)
	}
}

func TestSecretProtectorRejectsBadMasterKey(t *testing.T) {
	if _, err := NewSecretProtector("abcd"); err == nil {
		t.Fatal("expected short master key to fail")
	}
}
