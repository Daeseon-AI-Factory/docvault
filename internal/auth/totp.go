package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	totpPeriod = 30     // seconds
	totpDigits = 6
	totpSkew   = 1      // allow ±1 period (30s drift tolerance)
	secretLen  = 20     // 160 bits
)

// GenerateTOTPSecret creates a new random TOTP secret (base32 encoded).
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateTOTPURI builds the otpauth:// URI for QR code / manual entry.
// Format: otpauth://totp/DocVault:username?secret=BASE32&issuer=DocVault&digits=6&period=30
func GenerateTOTPURI(username, secret string) string {
	return fmt.Sprintf("otpauth://totp/DocVault:%s?secret=%s&issuer=DocVault&digits=%d&period=%d",
		username, secret, totpDigits, totpPeriod)
}

// ValidateTOTP checks if the provided code matches the current (or adjacent) time window.
func ValidateTOTP(secret, code string) bool {
	return ValidateTOTPAt(secret, code, time.Now())
}

// ValidateTOTPAt checks the code against a specific time (for testing).
func ValidateTOTPAt(secret, code string, t time.Time) bool {
	if len(code) != totpDigits {
		return false
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}

	counter := uint64(t.Unix()) / totpPeriod

	// Check current period and ±skew periods
	for i := -totpSkew; i <= totpSkew; i++ {
		expected := generateHOTP(key, counter+uint64(i))
		if expected == code {
			return true
		}
	}

	return false
}

// GenerateTOTPCode generates the current TOTP code (for testing/debugging).
func GenerateTOTPCode(secret string) (string, error) {
	return GenerateTOTPCodeAt(secret, time.Now())
}

// GenerateTOTPCodeAt generates a TOTP code for a specific time.
func GenerateTOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	counter := uint64(t.Unix()) / totpPeriod
	return generateHOTP(key, counter), nil
}

// generateHOTP implements HOTP (RFC 4226) — the core of TOTP.
func generateHOTP(key []byte, counter uint64) string {
	// Step 1: HMAC-SHA1(key, counter)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Step 2: Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Step 3: Modulo to get N digits
	return fmt.Sprintf("%0*d", totpDigits, code%1000000)
}

// GenerateRecoveryCodes creates 8 single-use recovery codes.
func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, 8)
	for i := range codes {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		// Format: XXXX-XXXX (alphanumeric, easy to type)
		raw := fmt.Sprintf("%010x", b)
		codes[i] = raw[:4] + "-" + raw[4:8]
	}
	return codes, nil
}
