package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Storage handles reading and writing encrypted file blobs to disk.
type Storage struct {
	basePath string
}

// NewStorage creates a Storage rooted at basePath.
func NewStorage(basePath string) (*Storage, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory %s: %w", basePath, err)
	}
	return &Storage{basePath: basePath}, nil
}

// StoragePath returns the on-disk path for a file version.
// Layout: {basePath}/{fileID}/{versionNumber}.enc
func (s *Storage) StoragePath(fileID int64, version int) string {
	return filepath.Join(s.basePath, fmt.Sprintf("%d", fileID), fmt.Sprintf("%d.enc", version))
}

// Write streams encrypted content to disk. Creates parent directories as needed.
func (s *Storage) Write(path string, key, nonce []byte, src io.Reader) (int64, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, fmt.Errorf("create storage dir %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, fmt.Errorf("create file %s: %w", path, err)
	}
	defer f.Close()

	counter := &countWriter{w: f}
	if err := EncryptStream(key, nonce, src, counter); err != nil {
		os.Remove(path)
		return 0, fmt.Errorf("encrypt and write: %w", err)
	}

	return counter.n, nil
}

// Read streams decrypted content from disk to dst.
func (s *Storage) Read(path string, key, nonce []byte, dst io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close()

	if err := DecryptStream(key, nonce, f, dst); err != nil {
		return fmt.Errorf("decrypt and read: %w", err)
	}

	return nil
}

// countWriter wraps a writer and counts bytes written.
type countWriter struct {
	w io.Writer
	n int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}
