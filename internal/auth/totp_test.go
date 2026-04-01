package auth

import (
	"testing"
	"time"
)

func TestGenerateTOTPSecret(t *testing.T) {
	s1, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	s2, _ := GenerateTOTPSecret()

	if s1 == s2 {
		t.Error("secrets should be unique")
	}
	if len(s1) < 20 {
		t.Errorf("secret too short: %d", len(s1))
	}
}

func TestGenerateTOTPURI(t *testing.T) {
	uri := GenerateTOTPURI("admin", "JBSWY3DPEHPK3PXP")
	expected := "otpauth://totp/DocVault:admin?secret=JBSWY3DPEHPK3PXP&issuer=DocVault&digits=6&period=30"
	if uri != expected {
		t.Errorf("got: %s\nwant: %s", uri, expected)
	}
}

func TestTOTPGenerateAndValidate(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	now := time.Now()

	code, err := GenerateTOTPCodeAt(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("code should be 6 digits, got %d: %s", len(code), code)
	}

	if !ValidateTOTPAt(secret, code, now) {
		t.Error("valid code should be accepted")
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	if ValidateTOTP(secret, "000000") && ValidateTOTP(secret, "999999") {
		t.Error("at least one of these should be rejected")
	}
}

func TestTOTPRejectsInvalidLength(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	if ValidateTOTP(secret, "12345") {
		t.Error("5-digit code should be rejected")
	}
	if ValidateTOTP(secret, "1234567") {
		t.Error("7-digit code should be rejected")
	}
}

func TestTOTPSkewTolerance(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	// Generate code for 25 seconds ago (within ±30s skew)
	past := now.Add(-25 * time.Second)
	code, _ := GenerateTOTPCodeAt(secret, past)

	if !ValidateTOTPAt(secret, code, now) {
		t.Error("code from 25 seconds ago should be accepted (within skew)")
	}
}

func TestTOTPRejectsExpiredCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Now()

	// Generate code for 90 seconds ago (outside ±30s skew)
	expired := now.Add(-90 * time.Second)
	code, _ := GenerateTOTPCodeAt(secret, expired)

	if ValidateTOTPAt(secret, code, now) {
		t.Error("code from 90 seconds ago should be rejected")
	}
}

func TestTOTPDeterministic(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	fixedTime := time.Unix(1234567890, 0)

	code1, _ := GenerateTOTPCodeAt(secret, fixedTime)
	code2, _ := GenerateTOTPCodeAt(secret, fixedTime)

	if code1 != code2 {
		t.Errorf("same secret+time should produce same code: %s vs %s", code1, code2)
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(codes) != 8 {
		t.Errorf("expected 8 codes, got %d", len(codes))
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if len(code) != 9 { // XXXX-XXXX
			t.Errorf("code should be 9 chars (XXXX-XXXX), got %d: %s", len(code), code)
		}
		if code[4] != '-' {
			t.Errorf("code should have dash at position 4: %s", code)
		}
		if seen[code] {
			t.Errorf("duplicate recovery code: %s", code)
		}
		seen[code] = true
	}
}

func TestTOTPRejectsInvalidSecret(t *testing.T) {
	if ValidateTOTP("not-valid-base32!!!", "123456") {
		t.Error("invalid secret should cause rejection")
	}
}
