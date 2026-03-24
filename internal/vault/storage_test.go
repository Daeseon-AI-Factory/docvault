package vault

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageWriteRead(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "docvault-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	key, _ := GenerateKey()
	nonce := make([]byte, 16)
	rand.Read(nonce)

	original := []byte("This is a test document for DocVault storage layer testing.")
	path := storage.StoragePath(42, 1)

	// Write
	written, err := storage.Write(path, key, nonce, bytes.NewReader(original))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written == 0 {
		t.Error("should have written bytes")
	}

	// Verify file exists on disk
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("encrypted file should exist on disk")
	}

	// Read
	var decrypted bytes.Buffer
	if err := storage.Read(path, key, nonce, &decrypted); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if !bytes.Equal(original, decrypted.Bytes()) {
		t.Error("decrypted content does not match original")
	}
}

func TestStoragePathStructure(t *testing.T) {
	storage := &Storage{basePath: "/vault"}

	path := storage.StoragePath(123, 4)
	expected := filepath.Join("/vault", "123", "4.enc")

	if path != expected {
		t.Errorf("StoragePath = %s, want %s", path, expected)
	}
}

func TestStorageDirectoryCreation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "docvault-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	deepPath := filepath.Join(tmpDir, "new", "nested", "vault")
	_, err = NewStorage(deepPath)
	if err != nil {
		t.Fatalf("NewStorage with nested path: %v", err)
	}

	info, err := os.Stat(deepPath)
	if err != nil {
		t.Fatalf("vault dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("vault path should be a directory")
	}
}
