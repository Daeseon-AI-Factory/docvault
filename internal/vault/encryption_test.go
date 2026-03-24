package vault

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("key length = %d, want %d", len(key), keySize)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(nonce) != nonceSize {
		t.Errorf("nonce length = %d, want %d", len(nonce), nonceSize)
	}
}

func TestEncryptDecryptStream(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 100},
		{"exact_chunk", chunkSize},
		{"large", chunkSize*3 + 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey()
			nonce := make([]byte, 16) // CTR uses 16-byte IV
			rand.Read(nonce)

			// Generate random plaintext
			plaintext := make([]byte, tt.size)
			rand.Read(plaintext)

			// Encrypt
			var encrypted bytes.Buffer
			err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted)
			if err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}

			// Decrypt
			var decrypted bytes.Buffer
			err = DecryptStream(key, nonce, bytes.NewReader(encrypted.Bytes()), &decrypted)
			if err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}

			// Verify
			if !bytes.Equal(plaintext, decrypted.Bytes()) {
				t.Error("decrypted content does not match original")
			}
		})
	}
}

func TestEncryptDecryptStreamLarge(t *testing.T) {
	key, _ := GenerateKey()
	nonce := make([]byte, 16)
	rand.Read(nonce)

	// 1MB file
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	// Encrypted size should match plaintext size (CTR mode)
	if encrypted.Len() != len(plaintext) {
		t.Errorf("encrypted size = %d, want %d", encrypted.Len(), len(plaintext))
	}

	var decrypted bytes.Buffer
	if err := DecryptStream(key, nonce, bytes.NewReader(encrypted.Bytes()), &decrypted); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Error("decrypted content does not match original")
	}
}

func TestWrongKeyFails(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	nonce := make([]byte, 16)
	rand.Read(nonce)

	plaintext := []byte("secret document content")

	var encrypted bytes.Buffer
	EncryptStream(key1, nonce, bytes.NewReader(plaintext), &encrypted)

	var decrypted bytes.Buffer
	DecryptStream(key2, nonce, bytes.NewReader(encrypted.Bytes()), &decrypted)

	if bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Error("decryption with wrong key should not produce original content")
	}
}

func BenchmarkEncryptStream(b *testing.B) {
	key, _ := GenerateKey()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	data := make([]byte, 10*1024*1024) // 10MB
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		EncryptStream(key, nonce, bytes.NewReader(data), io.Discard)
	}
}
