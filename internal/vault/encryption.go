package vault

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	keySize   = 32           // AES-256
	nonceSize = 12           // GCM standard nonce
	chunkSize = 64 * 1024    // 64 KiB plaintext per chunk
	tagSize   = 16           // GCM authentication tag
	maxChunks = 1 << 24      // 16M chunks × 64 KiB ≈ 1 TiB file limit
)

// GenerateKey creates a random AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// GenerateNonce creates a random 12-byte base nonce.
// Only the first 8 bytes are used by EncryptStream/DecryptStream; the rest
// is retained for compatibility with callers that store the full value.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// chunkNonce derives a 12-byte GCM nonce for a single chunk.
// Layout: [base[0:8]] || [chunk_index (3 bytes BE)] || [final flag (1 byte)]
// The final flag (0x01 only on the last chunk) prevents truncation attacks.
func chunkNonce(base []byte, index uint32, isFinal bool) []byte {
	n := make([]byte, nonceSize)
	copy(n, base[:8])
	n[8] = byte(index >> 16)
	n[9] = byte(index >> 8)
	n[10] = byte(index)
	if isFinal {
		n[11] = 1
	}
	return n
}

// EncryptStream encrypts src to dst using chunked AES-256-GCM.
//
// Plaintext is split into 64 KiB chunks; each chunk gets its own nonce
// derived from baseNonce and the chunk index, plus a GCM authentication tag.
// The final chunk (possibly empty) is marked in its nonce to defeat truncation.
//
// On-disk format: concatenated ciphertext chunks. The base nonce is NOT written —
// the caller must store and pass it back for decryption.
func EncryptStream(key, baseNonce []byte, src io.Reader, dst io.Writer) error {
	if len(baseNonce) < 8 {
		return fmt.Errorf("baseNonce must be ≥ 8 bytes, got %d", len(baseNonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	// Buffered reader lets us peek 1 byte ahead to detect EOF cleanly,
	// even when a chunk happens to align exactly with the input boundary.
	br := bufio.NewReaderSize(src, chunkSize+1)
	buf := make([]byte, chunkSize)

	for i := uint32(0); ; i++ {
		if i >= maxChunks {
			return fmt.Errorf("file exceeds maximum of %d chunks (~1 TiB)", maxChunks)
		}

		n, readErr := io.ReadFull(br, buf)

		isFinal := false
		switch readErr {
		case nil:
			// Full chunk read. Check if any data follows.
			if _, peekErr := br.Peek(1); peekErr == io.EOF {
				isFinal = true
			} else if peekErr != nil {
				return fmt.Errorf("peek after chunk %d: %w", i, peekErr)
			}
		case io.EOF, io.ErrUnexpectedEOF:
			// 0 or partial bytes at EOF — this is the final chunk.
			isFinal = true
		default:
			return fmt.Errorf("read chunk %d: %w", i, readErr)
		}

		ct := gcm.Seal(nil, chunkNonce(baseNonce, i, isFinal), buf[:n], nil)
		if _, err := dst.Write(ct); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}

		if isFinal {
			return nil
		}
	}
}

// DecryptStream decrypts chunked AES-256-GCM ciphertext from src to dst.
// Returns an error if any chunk fails authentication (tampering, truncation,
// reordering, or wrong key).
func DecryptStream(key, baseNonce []byte, src io.Reader, dst io.Writer) error {
	if len(baseNonce) < 8 {
		return fmt.Errorf("baseNonce must be ≥ 8 bytes, got %d", len(baseNonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	ctChunkSize := chunkSize + tagSize
	br := bufio.NewReaderSize(src, ctChunkSize+1)
	buf := make([]byte, ctChunkSize)

	for i := uint32(0); ; i++ {
		if i >= maxChunks {
			return fmt.Errorf("ciphertext exceeds maximum of %d chunks", maxChunks)
		}

		n, readErr := io.ReadFull(br, buf)

		isFinal := false
		switch readErr {
		case nil:
			if _, peekErr := br.Peek(1); peekErr == io.EOF {
				isFinal = true
			} else if peekErr != nil {
				return fmt.Errorf("peek after chunk %d: %w", i, peekErr)
			}
		case io.ErrUnexpectedEOF:
			isFinal = true
		case io.EOF:
			// Encryption always emits at least one chunk (≥ tagSize bytes).
			// EOF here means the stream was truncated before the final chunk.
			return fmt.Errorf("truncated ciphertext: missing final chunk")
		default:
			return fmt.Errorf("read chunk %d: %w", i, readErr)
		}

		if n < tagSize {
			return fmt.Errorf("chunk %d too small: %d bytes (need ≥ %d)", i, n, tagSize)
		}

		pt, err := gcm.Open(nil, chunkNonce(baseNonce, i, isFinal), buf[:n], nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}

		if _, err := dst.Write(pt); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}

		if isFinal {
			return nil
		}
	}
}
