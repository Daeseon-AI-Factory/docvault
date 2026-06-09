package folder

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
	userpkg "github.com/JasonAIFactory/Product024_JasonDRM/internal/user"
)

type Handler struct {
	repo   *Repository
	logger *slog.Logger
}

func NewHandler(repo *Repository, logger *slog.Logger) *Handler {
	return &Handler{repo: repo, logger: logger}
}

func (h *Handler) hasAccess(r *http.Request, authUser *auth.AuthUser, folderID int64, required Permission) (bool, error) {
	if authUser == nil {
		return false, nil
	}
	if authUser.Role == userpkg.RoleAdmin {
		return true, nil
	}
	return h.repo.CheckAccess(r.Context(), folderID, authUser.ID, required)
}

func (h *Handler) requireAccess(w http.ResponseWriter, r *http.Request, authUser *auth.AuthUser, folderID int64, required Permission) bool {
	allowed, err := h.hasAccess(r, authUser, folderID, required)
	if err != nil {
		h.logger.Error("folder: check access", "error", err, "folder_id", folderID, "user_id", authUser.ID)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return false
	}
	if !allowed {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return false
	}
	return true
}

type createFolderRequest struct {
	Name     string `json:"name"`
	ParentID *int64 `json:"parent_id,omitempty"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req createFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	// If creating under a parent, check write access
	if req.ParentID != nil {
		hasAccess, err := h.repo.CheckAccess(r.Context(), *req.ParentID, user.ID, PermWrite)
		if err != nil {
			h.logger.Error("create folder: check access", "error", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if !hasAccess && user.Role != userpkg.RoleAdmin {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
	}

	f := &Folder{
		Name:      req.Name,
		ParentID:  req.ParentID,
		CreatedBy: user.ID,
	}

	if err := h.repo.Create(r.Context(), f); err != nil {
		h.logger.Error("create folder", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(f)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "folderID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}

	f, err := h.repo.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, `{"error":"folder not found"}`, http.StatusNotFound)
		return
	}
	if !h.requireAccess(w, r, user, id, PermRead) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(f)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var parentID *int64
	if pidStr := r.URL.Query().Get("parent_id"); pidStr != "" {
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid parent_id"}`, http.StatusBadRequest)
			return
		}
		parentID = &pid
	}
	if parentID != nil && !h.requireAccess(w, r, user, *parentID, PermRead) {
		return
	}

	folders, err := h.repo.ListChildren(r.Context(), parentID)
	if err != nil {
		h.logger.Error("list folders", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	if user.Role != userpkg.RoleAdmin {
		filtered := folders[:0]
		for _, f := range folders {
			allowed, err := h.hasAccess(r, user, f.ID, PermRead)
			if err != nil {
				h.logger.Error("folder: filter list access", "error", err, "folder_id", f.ID, "user_id", user.ID)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			if allowed {
				filtered = append(filtered, f)
			}
		}
		folders = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"folders": folders,
	})
}

type updateFolderRequest struct {
	Name string `json:"name"`
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "folderID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}

	hasAccess, _ := h.repo.CheckAccess(r.Context(), id, user.ID, PermAdmin)
	if !hasAccess && user.Role != userpkg.RoleAdmin {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	var req updateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.Update(r.Context(), id, req.Name); err != nil {
		h.logger.Error("update folder", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "folderID")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}

	hasAccess, _ := h.repo.CheckAccess(r.Context(), id, user.ID, PermAdmin)
	if !hasAccess && user.Role != userpkg.RoleAdmin {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	if err := h.repo.SoftDelete(r.Context(), id); err != nil {
		h.logger.Error("delete folder", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Permission endpoints

type setPermissionRequest struct {
	UserID     int64      `json:"user_id"`
	Permission Permission `json:"permission"`
}

func (h *Handler) SetPermission(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "folderID")
	folderID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}

	hasAccess, _ := h.repo.CheckAccess(r.Context(), folderID, user.ID, PermAdmin)
	if !hasAccess && user.Role != userpkg.RoleAdmin {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	var req setPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Permission != PermRead && req.Permission != PermWrite && req.Permission != PermAdmin {
		http.Error(w, `{"error":"permission must be read, write, or admin"}`, http.StatusBadRequest)
		return
	}

	fp := &FolderPermission{
		FolderID:   folderID,
		UserID:     req.UserID,
		Permission: req.Permission,
		GrantedBy:  user.ID,
	}

	if err := h.repo.SetPermission(r.Context(), fp); err != nil {
		h.logger.Error("set permission", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(fp)
}

func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "folderID")
	folderID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}
	if !h.requireAccess(w, r, user, folderID, PermAdmin) {
		return
	}

	perms, err := h.repo.ListPermissions(r.Context(), folderID)
	if err != nil {
		h.logger.Error("list permissions", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"permissions": perms,
	})
}

func (h *Handler) RemovePermission(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	folderIDStr := chi.URLParam(r, "folderID")
	folderID, err := strconv.ParseInt(folderIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid folder ID"}`, http.StatusBadRequest)
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	targetUserID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid user ID"}`, http.StatusBadRequest)
		return
	}

	hasAccess, _ := h.repo.CheckAccess(r.Context(), folderID, user.ID, PermAdmin)
	if !hasAccess && user.Role != userpkg.RoleAdmin {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	if err := h.repo.RemovePermission(r.Context(), folderID, targetUserID); err != nil {
		h.logger.Error("remove permission", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
