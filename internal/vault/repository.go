package vault

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateFile(ctx context.Context, tx pgx.Tx, f *File) error {
	err := tx.QueryRow(ctx,
		`INSERT INTO files (folder_id, name, mime_type, size_bytes, sha256_hash, current_version, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, created_at, updated_at`,
		f.FolderID, f.Name, f.MimeType, f.SizeBytes, f.SHA256Hash, f.CurrentVersion, f.CreatedBy,
	).Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert file: %w", err)
	}
	return nil
}

func (r *Repository) CreateFileVersion(ctx context.Context, tx pgx.Tx, v *FileVersion) error {
	err := tx.QueryRow(ctx,
		`INSERT INTO file_versions (file_id, version_number, storage_path, size_bytes, sha256_hash, encrypted_key, nonce, uploaded_by, comment)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, created_at`,
		v.FileID, v.VersionNumber, v.StoragePath, v.SizeBytes, v.SHA256Hash, v.EncryptedKey, v.Nonce, v.UploadedBy, v.Comment,
	).Scan(&v.ID, &v.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert file version: %w", err)
	}
	return nil
}

func (r *Repository) GetFileByID(ctx context.Context, id int64) (*File, error) {
	var f File
	err := r.db.QueryRow(ctx,
		`SELECT id, folder_id, name, mime_type, size_bytes, sha256_hash, current_version,
		        is_checked_out, checked_out_by, checked_out_at, is_deleted, created_by, created_at, updated_at
		 FROM files WHERE id = $1 AND is_deleted = false`, id,
	).Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.SizeBytes, &f.SHA256Hash, &f.CurrentVersion,
		&f.IsCheckedOut, &f.CheckedOutBy, &f.CheckedOutAt, &f.IsDeleted, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get file %d: %w", id, err)
	}
	return &f, nil
}

func (r *Repository) GetFileVersion(ctx context.Context, fileID int64, version int) (*FileVersion, error) {
	var v FileVersion
	err := r.db.QueryRow(ctx,
		`SELECT id, file_id, version_number, storage_path, size_bytes, sha256_hash, encrypted_key, nonce, uploaded_by, comment, created_at
		 FROM file_versions WHERE file_id = $1 AND version_number = $2`, fileID, version,
	).Scan(&v.ID, &v.FileID, &v.VersionNumber, &v.StoragePath, &v.SizeBytes, &v.SHA256Hash, &v.EncryptedKey, &v.Nonce, &v.UploadedBy, &v.Comment, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get file version %d v%d: %w", fileID, version, err)
	}
	return &v, nil
}

func (r *Repository) GetLatestVersion(ctx context.Context, fileID int64) (*FileVersion, error) {
	var f File
	err := r.db.QueryRow(ctx, `SELECT current_version FROM files WHERE id = $1 AND is_deleted = false`, fileID).Scan(&f.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("get current version for file %d: %w", fileID, err)
	}
	return r.GetFileVersion(ctx, fileID, f.CurrentVersion)
}

func (r *Repository) ListFilesByFolder(ctx context.Context, folderID int64) ([]*File, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, folder_id, name, mime_type, size_bytes, sha256_hash, current_version,
		        is_checked_out, checked_out_by, checked_out_at, is_deleted, created_by, created_at, updated_at
		 FROM files WHERE folder_id = $1 AND is_deleted = false
		 ORDER BY name`, folderID,
	)
	if err != nil {
		return nil, fmt.Errorf("list files in folder %d: %w", folderID, err)
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.SizeBytes, &f.SHA256Hash, &f.CurrentVersion,
			&f.IsCheckedOut, &f.CheckedOutBy, &f.CheckedOutAt, &f.IsDeleted, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		files = append(files, &f)
	}
	return files, rows.Err()
}

func (r *Repository) ListVersions(ctx context.Context, fileID int64) ([]*FileVersion, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, file_id, version_number, storage_path, size_bytes, sha256_hash, encrypted_key, nonce, uploaded_by, comment, created_at
		 FROM file_versions WHERE file_id = $1
		 ORDER BY version_number DESC`, fileID,
	)
	if err != nil {
		return nil, fmt.Errorf("list versions for file %d: %w", fileID, err)
	}
	defer rows.Close()

	var versions []*FileVersion
	for rows.Next() {
		var v FileVersion
		if err := rows.Scan(&v.ID, &v.FileID, &v.VersionNumber, &v.StoragePath, &v.SizeBytes, &v.SHA256Hash, &v.EncryptedKey, &v.Nonce, &v.UploadedBy, &v.Comment, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		versions = append(versions, &v)
	}
	return versions, rows.Err()
}

func (r *Repository) UpdateFileVersion(ctx context.Context, tx pgx.Tx, fileID int64, version int, sizeBytes int64, sha256Hash string) error {
	_, err := tx.Exec(ctx,
		`UPDATE files SET current_version = $1, size_bytes = $2, sha256_hash = $3, updated_at = NOW()
		 WHERE id = $4`,
		version, sizeBytes, sha256Hash, fileID,
	)
	if err != nil {
		return fmt.Errorf("update file %d to version %d: %w", fileID, version, err)
	}
	return nil
}

func (r *Repository) SoftDeleteFile(ctx context.Context, fileID int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE files SET is_deleted = true, updated_at = NOW() WHERE id = $1`, fileID,
	)
	if err != nil {
		return fmt.Errorf("soft delete file %d: %w", fileID, err)
	}
	return nil
}

func (r *Repository) Checkout(ctx context.Context, fileID, userID int64) error {
	result, err := r.db.Exec(ctx,
		`UPDATE files SET is_checked_out = true, checked_out_by = $1, checked_out_at = NOW(), updated_at = NOW()
		 WHERE id = $2 AND is_deleted = false AND is_checked_out = false`,
		userID, fileID,
	)
	if err != nil {
		return fmt.Errorf("checkout file %d: %w", fileID, err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("file %d is already checked out or not found", fileID)
	}
	return nil
}

func (r *Repository) Checkin(ctx context.Context, fileID, userID int64) error {
	result, err := r.db.Exec(ctx,
		`UPDATE files SET is_checked_out = false, checked_out_by = NULL, checked_out_at = NULL, updated_at = NOW()
		 WHERE id = $1 AND is_deleted = false AND is_checked_out = true AND checked_out_by = $2`,
		fileID, userID,
	)
	if err != nil {
		return fmt.Errorf("checkin file %d: %w", fileID, err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("file %d is not checked out by user %d", fileID, userID)
	}
	return nil
}

func (r *Repository) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.Begin(ctx)
}
