package web

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

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/alert"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/folder"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
	"github.com/JasonAIFactory/Product024_JasonDRM/internal/vault"
)

// FormHandler handles HTML form submissions (POST) with redirects.
type FormHandler struct {
	vaultRepo    *vault.Repository
	vaultStorage *vault.Storage
	keyManager   *vault.KeyManager
	folderRepo   *folder.Repository
	userRepo     *user.Repository
	alertRepo    *alert.Repository
	logger       *slog.Logger
}

type FormHandlerDeps struct {
	VaultRepo    *vault.Repository
	VaultStorage *vault.Storage
	KeyManager   *vault.KeyManager
	FolderRepo   *folder.Repository
	UserRepo     *user.Repository
	AlertRepo    *alert.Repository
	Logger       *slog.Logger
}

func NewFormHandler(deps FormHandlerDeps) *FormHandler {
	return &FormHandler{
		vaultRepo:    deps.VaultRepo,
		vaultStorage: deps.VaultStorage,
		keyManager:   deps.KeyManager,
		folderRepo:   deps.FolderRepo,
		userRepo:     deps.UserRepo,
		alertRepo:    deps.AlertRepo,
		logger:       deps.Logger,
	}
}

func (h *FormHandler) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.AuthUser, bool) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	if u.Role != user.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return u, true
}

func (h *FormHandler) hasFolderAccess(r *http.Request, u *auth.AuthUser, folderID int64, required folder.Permission) (bool, error) {
	if u == nil {
		return false, nil
	}
	if u.Role == user.RoleAdmin {
		return true, nil
	}
	if h.folderRepo == nil {
		return false, nil
	}
	return h.folderRepo.CheckAccess(r.Context(), folderID, u.ID, required)
}

func (h *FormHandler) requireFolderAccess(w http.ResponseWriter, r *http.Request, u *auth.AuthUser, folderID int64, required folder.Permission) bool {
	allowed, err := h.hasFolderAccess(r, u, folderID, required)
	if err != nil {
		h.logger.Error("form: check folder access", "error", err, "folder_id", folderID, "user_id", u.ID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// UploadFile handles POST /files/upload (multipart form)
func (h *FormHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	folderIDStr := r.FormValue("folder_id")
	if folderIDStr == "" {
		http.Error(w, "folder_id is required", http.StatusBadRequest)
		return
	}
	folderID, err := strconv.ParseInt(folderIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid folder_id", http.StatusBadRequest)
		return
	}
	if !h.requireFolderAccess(w, r, u, folderID, folder.PermWrite) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)
	mpFile, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer mpFile.Close()

	comment := r.FormValue("comment")

	plainKey, encryptedKey, nonce, err := h.keyManager.GenerateFileKey()
	if err != nil {
		h.logger.Error("form upload: generate key", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	hasher := sha256.New()
	teeReader := io.TeeReader(mpFile, hasher)

	tx, err := h.vaultRepo.BeginTx(r.Context())
	if err != nil {
		h.logger.Error("form upload: begin tx", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	file := &vault.File{
		FolderID:       folderID,
		Name:           header.Filename,
		MimeType:       mimeType,
		CurrentVersion: 1,
		CreatedBy:      u.ID,
	}

	if err := h.vaultRepo.CreateFile(r.Context(), tx, file); err != nil {
		h.logger.Error("form upload: create file", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	storagePath := h.vaultStorage.StoragePath(file.ID, 1)
	contentNonce := make([]byte, 16)
	copy(contentNonce, nonce)
	if len(nonce) < 16 {
		contentNonce = append(nonce, make([]byte, 16-len(nonce))...)
	}

	encryptedSize, err := h.vaultStorage.Write(storagePath, plainKey, contentNonce, teeReader)
	if err != nil {
		h.logger.Error("form upload: write", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	if err := h.vaultRepo.UpdateFileVersion(r.Context(), tx, file.ID, 1, encryptedSize, sha256Hash); err != nil {
		h.logger.Error("form upload: update version", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	version := &vault.FileVersion{
		FileID:        file.ID,
		VersionNumber: 1,
		StoragePath:   storagePath,
		SizeBytes:     encryptedSize,
		SHA256Hash:    sha256Hash,
		EncryptedKey:  encryptedKey,
		Nonce:         nonce,
		UploadedBy:    u.ID,
		Comment:       comment,
	}

	if err := h.vaultRepo.CreateFileVersion(r.Context(), tx, version); err != nil {
		h.logger.Error("form upload: create version", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("form upload: commit", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	redirectURL := "/files"
	if folderID > 0 {
		redirectURL = fmt.Sprintf("/files?folder_id=%d", folderID)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// CheckoutFile handles POST /files/{fileID}/checkout
func (h *FormHandler) CheckoutFile(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid file ID", http.StatusBadRequest)
		return
	}
	file, err := h.vaultRepo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if !h.requireFolderAccess(w, r, u, file.FolderID, folder.PermWrite) {
		return
	}

	if err := h.vaultRepo.Checkout(r.Context(), fileID, u.ID); err != nil {
		h.logger.Error("form checkout", "error", err)
		http.Error(w, "file is already checked out or not found", http.StatusConflict)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/files/%d", fileID), http.StatusSeeOther)
}

// CheckinFile handles POST /files/{fileID}/checkin
func (h *FormHandler) CheckinFile(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	fileIDStr := chi.URLParam(r, "fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid file ID", http.StatusBadRequest)
		return
	}
	file, err := h.vaultRepo.GetFileByID(r.Context(), fileID)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if !h.requireFolderAccess(w, r, u, file.FolderID, folder.PermWrite) {
		return
	}

	// Check for new file version
	mpFile, _, err := r.FormFile("file")
	if err == nil {
		defer mpFile.Close()

		newVersion := file.CurrentVersion + 1
		comment := r.FormValue("comment")

		plainKey, encryptedKey, nonce, err := h.keyManager.GenerateFileKey()
		if err != nil {
			h.logger.Error("form checkin: generate key", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		hasher := sha256.New()
		teeReader := io.TeeReader(mpFile, hasher)

		storagePath := h.vaultStorage.StoragePath(fileID, newVersion)
		contentNonce := make([]byte, 16)
		copy(contentNonce, nonce)
		if len(nonce) < 16 {
			contentNonce = append(nonce, make([]byte, 16-len(nonce))...)
		}

		encryptedSize, err := h.vaultStorage.Write(storagePath, plainKey, contentNonce, teeReader)
		if err != nil {
			h.logger.Error("form checkin: write", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sha256Hash := hex.EncodeToString(hasher.Sum(nil))

		tx, err := h.vaultRepo.BeginTx(r.Context())
		if err != nil {
			h.logger.Error("form checkin: begin tx", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context())

		v := &vault.FileVersion{
			FileID:        fileID,
			VersionNumber: newVersion,
			StoragePath:   storagePath,
			SizeBytes:     encryptedSize,
			SHA256Hash:    sha256Hash,
			EncryptedKey:  encryptedKey,
			Nonce:         nonce,
			UploadedBy:    u.ID,
			Comment:       comment,
		}
		if err := h.vaultRepo.CreateFileVersion(r.Context(), tx, v); err != nil {
			h.logger.Error("form checkin: create version", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := h.vaultRepo.UpdateFileVersion(r.Context(), tx, fileID, newVersion, encryptedSize, sha256Hash); err != nil {
			h.logger.Error("form checkin: update file", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.logger.Error("form checkin: commit", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	if err := h.vaultRepo.Checkin(r.Context(), fileID, u.ID); err != nil {
		h.logger.Error("form checkin: release lock", "error", err)
		http.Error(w, "file is not checked out by you", http.StatusConflict)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/files/%d", fileID), http.StatusSeeOther)
}

// CreateFolder handles POST /folders/create
func (h *FormHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var parentID *int64
	if pidStr := r.FormValue("parent_id"); pidStr != "" && pidStr != "0" {
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid parent_id", http.StatusBadRequest)
			return
		}
		parentID = &pid
	}
	if parentID != nil && !h.requireFolderAccess(w, r, u, *parentID, folder.PermWrite) {
		return
	}

	f := &folder.Folder{
		Name:      name,
		ParentID:  parentID,
		CreatedBy: u.ID,
	}

	if err := h.folderRepo.Create(r.Context(), f); err != nil {
		h.logger.Error("form create folder", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	redirectURL := "/files"
	if parentID != nil {
		redirectURL = fmt.Sprintf("/files?folder_id=%d", *parentID)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// CreateUser handles POST /admin/users/create
func (h *FormHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	fullName := r.FormValue("full_name")
	role := user.Role(r.FormValue("role"))
	department := r.FormValue("department")

	if username == "" || email == "" || password == "" || fullName == "" {
		http.Error(w, "all fields required", http.StatusBadRequest)
		return
	}
	if role == "" {
		role = user.RoleEmployee
	}

	hash, err := user.HashPassword(password)
	if err != nil {
		h.logger.Error("form create user: hash", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	u := &user.User{
		Username: username, Email: email, PasswordHash: hash,
		FullName: fullName, Role: role, Department: department,
	}

	if err := h.userRepo.Create(r.Context(), u); err != nil {
		h.logger.Error("form create user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// CreateAlertRule handles POST /admin/alerts/rules/create
func (h *FormHandler) CreateAlertRule(w http.ResponseWriter, r *http.Request) {
	u, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	name := r.FormValue("name")
	eventType := r.FormValue("event_type")
	severity := alert.Severity(r.FormValue("severity"))
	description := r.FormValue("description")

	if name == "" || eventType == "" {
		http.Error(w, "name and event_type required", http.StatusBadRequest)
		return
	}
	if severity == "" {
		severity = alert.SeverityMedium
	}

	condition, _ := json.Marshal(map[string]interface{}{})

	rule := &alert.AlertRule{
		Name:        name,
		Description: description,
		EventType:   eventType,
		Condition:   condition,
		Severity:    severity,
		CreatedBy:   u.ID,
	}

	if err := h.alertRepo.CreateRule(r.Context(), rule); err != nil {
		h.logger.Error("form create rule", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/alerts", http.StatusSeeOther)
}

// AcknowledgeAlert handles POST /admin/alerts/{alertID}/acknowledge
func (h *FormHandler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	u, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	alertIDStr := chi.URLParam(r, "alertID")
	alertID, _ := strconv.ParseInt(alertIDStr, 10, 64)

	h.alertRepo.Acknowledge(r.Context(), alertID, u.ID)
	http.Redirect(w, r, "/admin/alerts", http.StatusSeeOther)
}

// EditUser handles POST /admin/users/{userID}/edit
func (h *FormHandler) EditUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	idStr := chi.URLParam(r, "userID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	existing, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if v := r.FormValue("full_name"); v != "" {
		existing.FullName = v
	}
	if v := r.FormValue("email"); v != "" {
		existing.Email = v
	}
	if v := r.FormValue("role"); v != "" {
		existing.Role = user.Role(v)
	}
	existing.Department = r.FormValue("department")
	existing.IsActive = r.FormValue("is_active") == "true"

	if err := h.userRepo.Update(r.Context(), existing); err != nil {
		h.logger.Error("form edit user", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// ResetPassword handles POST /admin/users/{userID}/reset-password
func (h *FormHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}

	idStr := chi.URLParam(r, "userID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "password is required", http.StatusBadRequest)
		return
	}

	hash, err := user.HashPassword(password)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := h.userRepo.UpdatePassword(r.Context(), id, hash); err != nil {
		h.logger.Error("form reset password", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d/edit", id), http.StatusSeeOther)
}
