package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// KeyManager handles envelope encryption: file keys are encrypted by the master key.
type KeyManager struct {
	masterKey []byte
}

// NewKeyManager creates a KeyManager from a hex-encoded master key.
func NewKeyManager(masterKeyHex string) (*KeyManager, error) {
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode master key hex: %w", err)
	}
	if len(masterKey) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", keySize, len(masterKey))
	}
	return &KeyManager{masterKey: masterKey}, nil
}

// GenerateFileKey creates a new random file encryption key and returns it
// along with its encrypted form (sealed by the master key).
func (km *KeyManager) GenerateFileKey() (plainKey, encryptedKey, nonce []byte, err error) {
	plainKey, err = GenerateKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate file key: %w", err)
	}

	encryptedKey, nonce, err = km.EncryptKey(plainKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt file key: %w", err)
	}

	return plainKey, encryptedKey, nonce, nil
}

// EncryptKey encrypts a file key using the master key with AES-256-GCM.
func (km *KeyManager) EncryptKey(plainKey []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(km.masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create master cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plainKey, nil)
	return ciphertext, nonce, nil
}

// DecryptKey decrypts a file key using the master key with AES-256-GCM.
func (km *KeyManager) DecryptKey(encryptedKey, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(km.masterKey)
	if err != nil {
		return nil, fmt.Errorf("create master cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plainKey, err := gcm.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt file key: %w", err)
	}

	return plainKey, nil
}
