package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
)

type Handler struct {
	repo       *Repository
	storage    *Storage
	keyManager *KeyManager
	logger     *slog.Logger
}

func NewHandler(repo *Repository, storage *Storage, km *KeyManager, logger *slog.Logger) *Handler {
	return &Handler{
		repo:       repo,
		storage:    storage,
		keyManager: km,
		logger:     logger,
	}
}

// Upload handles POST /api/files/upload?folder_id=X
// Expects multipart form with "file" field.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	folderIDStr := r.URL.Query().Get("folder_id")
	if folderIDStr == "" {
		http.Error(w, `{"error":"folder_id is required"}`, http.StatusBadRequest)
		return
	}
	folderID, err := strconv.ParseInt(folderIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder_id"}`, http.StatusBadRequest)
		return
	}

	// Limit upload to 500MB
	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)

	mpFile, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"file is required"}`, http.StatusBadRequest)
		return
	}
	defer mpFile.Close()

	comment := r.FormValue("comment")

	// Generate file encryption key (envelope encryption)
	plainKey, encryptedKey, nonce, err := h.keyManager.GenerateFileKey()
	if err != nil {
		h.logger.Error("upload: generate file key", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Hash the original content while streaming
	hasher := sha256.New()
	teeReader := io.TeeReader(mpFile, hasher)

	// Begin transaction
	tx, err := h.repo.BeginTx(r.Context())
	if err != nil {
		h.logger.Error("upload: begin tx", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// Create file record
	file := &File{
		FolderID:       folderID,
		Name:           header.Filename,
		MimeType:       header.Header.Get("Content-Type"),
		CurrentVersion: 1,
		CreatedBy:      user.ID,
	}
	if file.MimeType == "" {
		file.MimeType = "application/octet-stream"
	}

	if err := h.repo.CreateFile(r.Context(), tx, file); err != nil {
		h.logger.Error("upload: create file record", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Stream encrypt to disk
	storagePath := h.storage.StoragePath(file.ID, 1)

	// Generate a separate nonce for file content encryption (CTR mode uses 16-byte IV)
	contentNonce := make([]byte, 16) // AES block size for CTR
	copy(contentNonce, nonce)
	if len(contentNonce) < 16 {
		// Pad with zeros (nonce from GCM is 12 bytes, CTR needs 16)
		contentNonce = append(nonce, make([]byte, 16-len(nonce))...)
	}

	encryptedSize, err := h.storage.Write(storagePath, plainKey, contentNonce, teeReader)
	if err != nil {
		h.logger.Error("upload: write encrypted file", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	// Update file with hash and size
	file.SHA256Hash = sha256Hash
	file.SizeBytes = encryptedSize

	if err := h.repo.UpdateFileVersion(r.Context(), tx, file.ID, 1, encryptedSize, sha256Hash); err != nil {
		h.logger.Error("upload: update file record", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Create version record
	version := &FileVersion{
		FileID:        file.ID,
		VersionNumber: 1,
		StoragePath:   storagePath,
		SizeBytes:     encryptedSize,
		SHA256Hash:    sha256Hash,
		EncryptedKey:  encryptedKey,
		Nonce:         nonce,
		UploadedBy:    user.ID,
		Comment:       comment,
	}

	if err := h.repo.CreateFileVersion(r.Context(), tx, version); err != nil {
		h.logger.Error("upload: create version record", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("upload: commit tx", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file":    file,
		"version": version,
	})
}

// Download handles GET /api/files/{fileID}/download?version=X
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	file, err := h.repo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		return
	}

	// Determine which version to download
	var version *FileVersion
	versionStr := r.URL.Query().Get("version")
	if versionStr != "" {
		v, err := strconv.Atoi(versionStr)
		if err != nil {
			http.Error(w, `{"error":"invalid version"}`, http.StatusBadRequest)
			return
		}
		version, err = h.repo.GetFileVersion(r.Context(), fileID, v)
		if err != nil {
			http.Error(w, `{"error":"version not found"}`, http.StatusNotFound)
			return
		}
	} else {
		version, err = h.repo.GetLatestVersion(r.Context(), fileID)
		if err != nil {
			http.Error(w, `{"error":"version not found"}`, http.StatusNotFound)
			return
		}
	}

	// Decrypt the file key using master key
	plainKey, err := h.keyManager.DecryptKey(version.EncryptedKey, version.Nonce)
	if err != nil {
		h.logger.Error("download: decrypt file key", "error", err, "file_id", fileID)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Build CTR nonce from the GCM nonce
	contentNonce := make([]byte, 16)
	copy(contentNonce, version.Nonce)
	if len(contentNonce) < 16 {
		contentNonce = append(version.Nonce, make([]byte, 16-len(version.Nonce))...)
	}

	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Name))

	if err := h.storage.Read(version.StoragePath, plainKey, contentNonce, w); err != nil {
		h.logger.Error("download: read and decrypt", "error", err, "file_id", fileID)
		return
	}
}

// GetFile handles GET /api/files/{fileID}
func (h *Handler) GetFile(w http.ResponseWriter, r *http.Request) {
	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	file, err := h.repo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		return
	}

	versions, err := h.repo.ListVersions(r.Context(), fileID)
	if err != nil {
		h.logger.Error("get file: list versions", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file":     file,
		"versions": versions,
	})
}

// ListFiles handles GET /api/files?folder_id=X
func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {
	folderIDStr := r.URL.Query().Get("folder_id")
	if folderIDStr == "" {
		http.Error(w, `{"error":"folder_id is required"}`, http.StatusBadRequest)
		return
	}
	folderID, err := strconv.ParseInt(folderIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder_id"}`, http.StatusBadRequest)
		return
	}

	files, err := h.repo.ListFilesByFolder(r.Context(), folderID)
	if err != nil {
		h.logger.Error("list files", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
	})
}

// DeleteFile handles DELETE /api/files/{fileID} (soft delete)
func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	if _, err := h.repo.GetFileByID(r.Context(), fileID); err != nil {
		http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		return
	}

	if err := h.repo.SoftDeleteFile(r.Context(), fileID); err != nil {
		h.logger.Error("delete file", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Checkout handles POST /api/files/{fileID}/checkout
func (h *Handler) Checkout(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.Checkout(r.Context(), fileID, user.ID); err != nil {
		h.logger.Error("checkout", "error", err, "file_id", fileID)
		http.Error(w, `{"error":"file is already checked out or not found"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "file checked out",
		"file_id": fileID,
	})
}

// Checkin handles POST /api/files/{fileID}/checkin
// Optionally accepts a new file version via multipart form.
func (h *Handler) Checkin(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	file, err := h.repo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		return
	}

	// Check if there's a new file version uploaded
	mpFile, _, err := r.FormFile("file")
	if err == nil {
		defer mpFile.Close()

		// Upload new version
		newVersion := file.CurrentVersion + 1
		comment := r.FormValue("comment")

		plainKey, encryptedKey, nonce, err := h.keyManager.GenerateFileKey()
		if err != nil {
			h.logger.Error("checkin: generate key", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		hasher := sha256.New()
		teeReader := io.TeeReader(mpFile, hasher)

		storagePath := h.storage.StoragePath(fileID, newVersion)
		contentNonce := make([]byte, 16)
		copy(contentNonce, nonce)
		if len(contentNonce) < 16 {
			contentNonce = append(nonce, make([]byte, 16-len(nonce))...)
		}

		encryptedSize, err := h.storage.Write(storagePath, plainKey, contentNonce, teeReader)
		if err != nil {
			h.logger.Error("checkin: write file", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		sha256Hash := hex.EncodeToString(hasher.Sum(nil))

		tx, err := h.repo.BeginTx(r.Context())
		if err != nil {
			h.logger.Error("checkin: begin tx", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context())

		version := &FileVersion{
			FileID:        fileID,
			VersionNumber: newVersion,
			StoragePath:   storagePath,
			SizeBytes:     encryptedSize,
			SHA256Hash:    sha256Hash,
			EncryptedKey:  encryptedKey,
			Nonce:         nonce,
			UploadedBy:    user.ID,
			Comment:       comment,
		}

		if err := h.repo.CreateFileVersion(r.Context(), tx, version); err != nil {
			h.logger.Error("checkin: create version", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		if err := h.repo.UpdateFileVersion(r.Context(), tx, fileID, newVersion, encryptedSize, sha256Hash); err != nil {
			h.logger.Error("checkin: update file", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			h.logger.Error("checkin: commit", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
	}

	// Release checkout lock
	if err := h.repo.Checkin(r.Context(), fileID, user.ID); err != nil {
		h.logger.Error("checkin: release lock", "error", err, "file_id", fileID)
		http.Error(w, `{"error":"file is not checked out by you"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "file checked in",
		"file_id": fileID,
	})
}
