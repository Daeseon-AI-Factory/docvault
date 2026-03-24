package vault

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testMasterKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return hex.EncodeToString(key)
}

func TestNewKeyManager(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		km, err := NewKeyManager(testMasterKey())
		if err != nil {
			t.Fatalf("NewKeyManager: %v", err)
		}
		if km == nil {
			t.Fatal("expected non-nil KeyManager")
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := NewKeyManager("not-hex")
		if err == nil {
			t.Error("expected error for invalid hex")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		_, err := NewKeyManager("aabbccdd")
		if err == nil {
			t.Error("expected error for wrong key length")
		}
	})
}

func TestGenerateFileKey(t *testing.T) {
	km, _ := NewKeyManager(testMasterKey())

	plainKey, encryptedKey, nonce, err := km.GenerateFileKey()
	if err != nil {
		t.Fatalf("GenerateFileKey: %v", err)
	}

	if len(plainKey) != keySize {
		t.Errorf("plain key length = %d, want %d", len(plainKey), keySize)
	}
	if len(encryptedKey) == 0 {
		t.Error("encrypted key should not be empty")
	}
	if len(nonce) == 0 {
		t.Error("nonce should not be empty")
	}

	// Encrypted key should be longer than plain key (GCM adds auth tag)
	if len(encryptedKey) <= len(plainKey) {
		t.Error("encrypted key should be longer than plain key (GCM auth tag)")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	km, _ := NewKeyManager(testMasterKey())

	originalKey, _ := GenerateKey()

	encrypted, nonce, err := km.EncryptKey(originalKey)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	decrypted, err := km.DecryptKey(encrypted, nonce)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}

	if !bytes.Equal(originalKey, decrypted) {
		t.Error("decrypted key does not match original")
	}
}

func TestDecryptKeyWithWrongNonce(t *testing.T) {
	km, _ := NewKeyManager(testMasterKey())

	originalKey, _ := GenerateKey()
	encrypted, _, _ := km.EncryptKey(originalKey)

	// Use a different nonce
	wrongNonce := make([]byte, 12)
	_, err := km.DecryptKey(encrypted, wrongNonce)
	if err == nil {
		t.Error("expected error when decrypting with wrong nonce")
	}
}

func TestEnvelopeEncryptionRoundTrip(t *testing.T) {
	km, _ := NewKeyManager(testMasterKey())

	// Simulate full envelope encryption flow
	plainKey, encryptedKey, nonce, _ := km.GenerateFileKey()

	// Use plainKey to encrypt a file
	fileContent := []byte("CAD drawing binary data here...")
	fileNonce := make([]byte, 16)
	copy(fileNonce, nonce)
	if len(fileNonce) < 16 {
		fileNonce = append(nonce, make([]byte, 16-len(nonce))...)
	}

	var encrypted bytes.Buffer
	EncryptStream(plainKey, fileNonce, bytes.NewReader(fileContent), &encrypted)

	// Later: recover the file key from storage
	recoveredKey, err := km.DecryptKey(encryptedKey, nonce)
	if err != nil {
		t.Fatalf("recover key: %v", err)
	}

	// Decrypt the file
	var decrypted bytes.Buffer
	DecryptStream(recoveredKey, fileNonce, bytes.NewReader(encrypted.Bytes()), &decrypted)

	if !bytes.Equal(fileContent, decrypted.Bytes()) {
		t.Error("full envelope encryption roundtrip failed")
	}
}
