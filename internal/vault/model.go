package vault

import "time"

type File struct {
	ID            int64     `json:"id"`
	FolderID      int64     `json:"folder_id"`
	Name          string    `json:"name"`
	MimeType      string    `json:"mime_type"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256Hash    string    `json:"sha256_hash"`
	CurrentVersion int      `json:"current_version"`
	IsCheckedOut  bool      `json:"is_checked_out"`
	CheckedOutBy  *int64    `json:"checked_out_by,omitempty"`
	CheckedOutAt  *time.Time `json:"checked_out_at,omitempty"`
	IsDeleted     bool      `json:"-"`
	CreatedBy     int64     `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type FileVersion struct {
	ID            int64     `json:"id"`
	FileID        int64     `json:"file_id"`
	VersionNumber int       `json:"version_number"`
	StoragePath   string    `json:"-"`
	SizeBytes     int64     `json:"size_bytes"`
	SHA256Hash    string    `json:"sha256_hash"`
	EncryptedKey  []byte    `json:"-"`
	Nonce         []byte    `json:"-"`
	UploadedBy    int64     `json:"uploaded_by"`
	Comment       string    `json:"comment"`
	CreatedAt     time.Time `json:"created_at"`
}
