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
		{"sub_chunk", chunkSize - 1},
		{"exact_chunk", chunkSize},
		{"chunk_plus_one", chunkSize + 1},
		{"two_chunks_exact", chunkSize * 2},
		{"large", chunkSize*3 + 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey()
			nonce, _ := GenerateNonce()

			plaintext := make([]byte, tt.size)
			rand.Read(plaintext)

			var encrypted bytes.Buffer
			if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}

			// Encrypted size = plaintext + (GCM tag × number of chunks).
			// Number of chunks = ceil(size/chunkSize), with a minimum of 1
			// so that empty input still produces a final tag.
			expectedChunks := (tt.size + chunkSize - 1) / chunkSize
			if expectedChunks == 0 {
				expectedChunks = 1
			}
			expectedSize := tt.size + expectedChunks*tagSize
			if encrypted.Len() != expectedSize {
				t.Errorf("encrypted size = %d, want %d (%d plaintext + %d chunks × %d tag)",
					encrypted.Len(), expectedSize, tt.size, expectedChunks, tagSize)
			}

			var decrypted bytes.Buffer
			if err := DecryptStream(key, nonce, bytes.NewReader(encrypted.Bytes()), &decrypted); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted.Bytes()) {
				t.Error("decrypted content does not match original")
			}
		})
	}
}

func TestEncryptDecryptStreamLarge(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	// 1 MiB file
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
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
	nonce, _ := GenerateNonce()

	plaintext := []byte("secret document content")

	var encrypted bytes.Buffer
	if err := EncryptStream(key1, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var decrypted bytes.Buffer
	err := DecryptStream(key2, nonce, bytes.NewReader(encrypted.Bytes()), &decrypted)
	if err == nil {
		t.Error("decryption with wrong key should return an error, got nil")
	}
}

func TestWrongNonceFails(t *testing.T) {
	key, _ := GenerateKey()
	nonce1, _ := GenerateNonce()
	nonce2, _ := GenerateNonce()

	plaintext := []byte("secret document content")

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce1, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	var decrypted bytes.Buffer
	err := DecryptStream(key, nonce2, bytes.NewReader(encrypted.Bytes()), &decrypted)
	if err == nil {
		t.Error("decryption with wrong nonce should return an error, got nil")
	}
}

func TestTamperDetection(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	plaintext := make([]byte, chunkSize*2+100)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	cases := []struct {
		name        string
		mutateAt    int
		description string
	}{
		{"first_chunk_body", 100, "flip a bit in chunk 0 body"},
		{"first_chunk_tag", chunkSize + 5, "flip a bit in chunk 0 auth tag"},
		{"middle_chunk_body", chunkSize + tagSize + 50, "flip a bit in chunk 1 body"},
		{"final_chunk", chunkSize*2 + tagSize*2 + 10, "flip a bit in final chunk"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, encrypted.Len())
			copy(tampered, encrypted.Bytes())
			if tc.mutateAt >= len(tampered) {
				t.Skipf("mutation offset %d out of range", tc.mutateAt)
			}
			tampered[tc.mutateAt] ^= 0xFF

			var out bytes.Buffer
			err := DecryptStream(key, nonce, bytes.NewReader(tampered), &out)
			if err == nil {
				t.Errorf("expected decryption error after tampering (%s), got nil", tc.description)
			}
		})
	}
}

func TestTruncationDetection(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	// Three chunks: 2 full + 1 partial.
	plaintext := make([]byte, chunkSize*2+50)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	// Truncate: remove the final chunk (which has the "final" flag set).
	// Decryption should fail because chunk 1 would be treated as final
	// using a nonce that doesn't match what was used during encryption.
	truncated := encrypted.Bytes()[:chunkSize+tagSize+chunkSize+tagSize]

	var out bytes.Buffer
	err := DecryptStream(key, nonce, bytes.NewReader(truncated), &out)
	if err == nil {
		t.Error("expected decryption error after truncation, got nil")
	}
}

func TestChunkReorderDetection(t *testing.T) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()

	plaintext := make([]byte, chunkSize*2)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	if err := EncryptStream(key, nonce, bytes.NewReader(plaintext), &encrypted); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}

	// Swap chunk 0 and chunk 1. Each chunk is chunkSize+tagSize bytes.
	// Final chunk for plaintext = 2*chunkSize is an empty chunk (tagSize bytes).
	ctChunk := chunkSize + tagSize
	reordered := make([]byte, encrypted.Len())
	copy(reordered[0:ctChunk], encrypted.Bytes()[ctChunk:ctChunk*2])
	copy(reordered[ctChunk:ctChunk*2], encrypted.Bytes()[0:ctChunk])
	copy(reordered[ctChunk*2:], encrypted.Bytes()[ctChunk*2:])

	var out bytes.Buffer
	err := DecryptStream(key, nonce, bytes.NewReader(reordered), &out)
	if err == nil {
		t.Error("expected decryption error after chunk reorder, got nil")
	}
}

func TestShortNonceRejected(t *testing.T) {
	key, _ := GenerateKey()
	shortNonce := make([]byte, 4)

	var out bytes.Buffer
	err := EncryptStream(key, shortNonce, bytes.NewReader([]byte("data")), &out)
	if err == nil {
		t.Error("expected error for nonce shorter than 8 bytes, got nil")
	}
}

func BenchmarkEncryptStream(b *testing.B) {
	key, _ := GenerateKey()
	nonce, _ := GenerateNonce()
	data := make([]byte, 10*1024*1024) // 10 MiB
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := EncryptStream(key, nonce, bytes.NewReader(data), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
