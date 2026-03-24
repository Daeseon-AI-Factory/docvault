package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
	chunkSize = 64 * 1024 // 64KB chunks for streaming
)

// GenerateKey creates a random AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// GenerateNonce creates a random GCM nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// EncryptStream encrypts data from src to dst using AES-256-CTR streaming.
// This avoids loading the entire file into memory.
func EncryptStream(key, nonce []byte, src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	stream := cipher.NewCTR(block, nonce)
	writer := &cipher.StreamWriter{S: stream, W: dst}

	if _, err := io.Copy(writer, src); err != nil {
		return fmt.Errorf("encrypt stream: %w", err)
	}

	return nil
}

// DecryptStream decrypts data from src to dst using AES-256-CTR streaming.
func DecryptStream(key, nonce []byte, src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	stream := cipher.NewCTR(block, nonce)
	reader := &cipher.StreamReader{S: stream, R: src}

	if _, err := io.Copy(dst, reader); err != nil {
		return fmt.Errorf("decrypt stream: %w", err)
	}

	return nil
}
