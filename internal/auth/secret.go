package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const protectedSecretPrefix = "enc:v1:"

// SecretProtector encrypts small authentication secrets with the DocVault
// master key. Values without the enc:v1 prefix are treated as legacy plaintext
// so existing TOTP enrollments keep working until they are rotated.
type SecretProtector struct {
	key []byte
}

func NewSecretProtector(masterKeyHex string) (*SecretProtector, error) {
	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	return &SecretProtector{key: key}, nil
}

func (p *SecretProtector) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if p == nil {
		return plaintext, nil
	}
	gcm, err := p.gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return protectedSecretPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (p *SecretProtector) Open(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, protectedSecretPrefix) {
		return stored, nil
	}
	if p == nil {
		return "", fmt.Errorf("encrypted secret requires a secret protector")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, protectedSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decode protected secret: %w", err)
	}
	gcm, err := p.gcm()
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("protected secret is too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt protected secret: %w", err)
	}
	return string(plaintext), nil
}

func IsProtectedSecret(stored string) bool {
	return strings.HasPrefix(stored, protectedSecretPrefix)
}

func (p *SecretProtector) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm, nil
}
