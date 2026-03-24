package audit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	repo   *Repository
	logger *slog.Logger
}

func NewHandler(repo *Repository, logger *slog.Logger) *Handler {
	return &Handler{repo: repo, logger: logger}
}

// UserTimeline handles GET /api/audit/users/{userID}
func (h *Handler) UserTimeline(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r,"userID")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid user ID"}`, http.StatusBadRequest)
		return
	}

	limit, offset := parsePagination(r)

	logs, err := h.repo.Search(r.Context(), SearchParams{
		UserID: &userID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		h.logger.Error("user timeline", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}

// FileTimeline handles GET /api/audit/files/{fileID}
func (h *Handler) FileTimeline(w http.ResponseWriter, r *http.Request) {
	fileIDStr := chi.URLParam(r,"fileID")
	fileID, err := strconv.ParseInt(fileIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid file ID"}`, http.StatusBadRequest)
		return
	}

	limit, offset := parsePagination(r)
	targetType := "file"

	logs, err := h.repo.Search(r.Context(), SearchParams{
		TargetType: &targetType,
		TargetID:   &fileID,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		h.logger.Error("file timeline", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}

// Search handles GET /api/audit/search?action=&from=&to=&limit=&offset=
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	params := SearchParams{}

	if v := r.URL.Query().Get("user_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			params.UserID = &id
		}
	}
	if v := r.URL.Query().Get("action"); v != "" {
		a := Action(v)
		params.Action = &a
	}
	if v := r.URL.Query().Get("target_type"); v != "" {
		params.TargetType = &v
	}
	if v := r.URL.Query().Get("target_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			params.TargetID = &id
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.To = &t
		}
	}

	params.Limit, params.Offset = parsePagination(r)

	logs, err := h.repo.Search(r.Context(), params)
	if err != nil {
		h.logger.Error("audit search", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}

// Dashboard handles GET /api/audit/dashboard
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := h.repo.GetDashboardStats(r.Context())
	if err != nil {
		h.logger.Error("audit dashboard", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func parsePagination(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
