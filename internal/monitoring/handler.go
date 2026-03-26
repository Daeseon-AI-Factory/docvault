package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler provides HTTP endpoints for monitoring config CRUD.
type Handler struct {
	db     *pgxpool.Pool
	repo   *Repository
	logger *slog.Logger
}

func NewHandler(db *pgxpool.Pool, repo *Repository, logger *slog.Logger) *Handler {
	return &Handler{db: db, repo: repo, logger: logger}
}

// --- Process Groups ---

func (h *Handler) ListProcessGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, group_name, process_name, display_name, is_active
		 FROM monitoring_process_groups ORDER BY group_name, process_name`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		ID          int64  `json:"id"`
		GroupName   string `json:"group_name"`
		ProcessName string `json:"process_name"`
		DisplayName string `json:"display_name"`
		IsActive    bool   `json:"is_active"`
	}
	var results []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.GroupName, &r.ProcessName, &r.DisplayName, &r.IsActive); err == nil {
			results = append(results, r)
		}
	}
	writeJSON(w, results)
}

func (h *Handler) AddProcessGroup(w http.ResponseWriter, r *http.Request) {
	groupName := r.FormValue("group_name")
	processName := r.FormValue("process_name")
	displayName := r.FormValue("display_name")

	if groupName == "" || processName == "" || displayName == "" {
		http.Error(w, "group_name, process_name, display_name required", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec(r.Context(),
		`INSERT INTO monitoring_process_groups (group_name, process_name, display_name)
		 VALUES ($1, $2, $3) ON CONFLICT (group_name, process_name) DO UPDATE SET display_name = $3, is_active = true`,
		groupName, processName, displayName)
	if err != nil {
		h.logger.Error("add process group", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) DeleteProcessGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `DELETE FROM monitoring_process_groups WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) ToggleProcessGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `UPDATE monitoring_process_groups SET is_active = NOT is_active WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

// --- Extensions ---

func (h *Handler) ListExtensions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, category, extension, display_name, is_sensitive, is_active
		 FROM monitoring_extensions ORDER BY category, extension`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		ID          int64  `json:"id"`
		Category    string `json:"category"`
		Extension   string `json:"extension"`
		DisplayName string `json:"display_name"`
		IsSensitive bool   `json:"is_sensitive"`
		IsActive    bool   `json:"is_active"`
	}
	var results []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.Category, &r.Extension, &r.DisplayName, &r.IsSensitive, &r.IsActive); err == nil {
			results = append(results, r)
		}
	}
	writeJSON(w, results)
}

func (h *Handler) AddExtension(w http.ResponseWriter, r *http.Request) {
	category := r.FormValue("category")
	ext := r.FormValue("extension")
	displayName := r.FormValue("display_name")
	isSensitive := r.FormValue("is_sensitive") == "true"

	if category == "" || ext == "" || displayName == "" {
		http.Error(w, "category, extension, display_name required", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec(r.Context(),
		`INSERT INTO monitoring_extensions (category, extension, display_name, is_sensitive)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (extension) DO UPDATE SET category = $1, display_name = $3, is_sensitive = $4, is_active = true`,
		category, ext, displayName, isSensitive)
	if err != nil {
		h.logger.Error("add extension", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) DeleteExtension(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `DELETE FROM monitoring_extensions WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) ToggleExtension(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `UPDATE monitoring_extensions SET is_active = NOT is_active WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

// --- Paths ---

func (h *Handler) AddPath(w http.ResponseWriter, r *http.Request) {
	pathType := r.FormValue("path_type")
	pathPattern := r.FormValue("path_pattern")
	desc := r.FormValue("description")

	if pathType == "" || pathPattern == "" {
		http.Error(w, "path_type and path_pattern required", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec(r.Context(),
		`INSERT INTO monitoring_paths (path_type, path_pattern, description) VALUES ($1, $2, $3)`,
		pathType, pathPattern, desc)
	if err != nil {
		h.logger.Error("add path", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) DeletePath(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `DELETE FROM monitoring_paths WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

// --- Disguise Rules ---

func (h *Handler) AddDisguiseRule(w http.ResponseWriter, r *http.Request) {
	fromCategory := r.FormValue("from_category")
	toExt := r.FormValue("to_extension")

	if fromCategory == "" || toExt == "" {
		http.Error(w, "from_category and to_extension required", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec(r.Context(),
		`INSERT INTO monitoring_ext_disguise (from_category, to_extension) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		fromCategory, toExt)
	if err != nil {
		h.logger.Error("add disguise rule", "error", err)
	}
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

func (h *Handler) DeleteDisguiseRule(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h.db.Exec(r.Context(), `DELETE FROM monitoring_ext_disguise WHERE id = $1`, id)
	h.invalidateCache(r.Context())
	http.Redirect(w, r, "/admin/monitoring", http.StatusSeeOther)
}

// --- Summary (for admin page) ---

func (h *Handler) GetSummary(ctx context.Context) (*ConfigSummary, error) {
	s := &ConfigSummary{}

	// Process groups
	rows, err := h.db.Query(ctx,
		`SELECT id, group_name, process_name, display_name, is_active
		 FROM monitoring_process_groups ORDER BY group_name, process_name`)
	if err != nil {
		return nil, fmt.Errorf("list process groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p ProcessRow
		if err := rows.Scan(&p.ID, &p.GroupName, &p.ProcessName, &p.DisplayName, &p.IsActive); err == nil {
			s.Processes = append(s.Processes, p)
		}
	}
	rows.Close()

	// Extensions
	rows2, err := h.db.Query(ctx,
		`SELECT id, category, extension, display_name, is_sensitive, is_active
		 FROM monitoring_extensions ORDER BY category, extension`)
	if err != nil {
		return nil, fmt.Errorf("list extensions: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var e ExtensionRow
		if err := rows2.Scan(&e.ID, &e.Category, &e.Extension, &e.DisplayName, &e.IsSensitive, &e.IsActive); err == nil {
			s.Extensions = append(s.Extensions, e)
		}
	}
	rows2.Close()

	// Paths
	rows3, err := h.db.Query(ctx,
		`SELECT id, path_type, path_pattern, description, is_active
		 FROM monitoring_paths ORDER BY path_type`)
	if err != nil {
		return nil, fmt.Errorf("list paths: %w", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var p PathRow
		if err := rows3.Scan(&p.ID, &p.PathType, &p.PathPattern, &p.Description, &p.IsActive); err == nil {
			s.Paths = append(s.Paths, p)
		}
	}
	rows3.Close()

	// Disguise rules
	rows4, err := h.db.Query(ctx,
		`SELECT id, from_category, to_extension, is_active
		 FROM monitoring_ext_disguise ORDER BY from_category, to_extension`)
	if err != nil {
		return nil, fmt.Errorf("list disguise rules: %w", err)
	}
	defer rows4.Close()
	for rows4.Next() {
		var d DisguiseRow
		if err := rows4.Scan(&d.ID, &d.FromCategory, &d.ToExtension, &d.IsActive); err == nil {
			s.DisguiseRules = append(s.DisguiseRules, d)
		}
	}
	rows4.Close()

	return s, nil
}

// invalidateCache forces the config cache to reload on next access.
func (h *Handler) invalidateCache(ctx context.Context) {
	h.repo.Reload(ctx)
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// --- Row types for admin page ---

type ConfigSummary struct {
	Processes     []ProcessRow
	Extensions    []ExtensionRow
	Paths         []PathRow
	DisguiseRules []DisguiseRow
}

type ProcessRow struct {
	ID          int64  `json:"id"`
	GroupName   string `json:"group_name"`
	ProcessName string `json:"process_name"`
	DisplayName string `json:"display_name"`
	IsActive    bool   `json:"is_active"`
}

type ExtensionRow struct {
	ID          int64  `json:"id"`
	Category    string `json:"category"`
	Extension   string `json:"extension"`
	DisplayName string `json:"display_name"`
	IsSensitive bool   `json:"is_sensitive"`
	IsActive    bool   `json:"is_active"`
}

type PathRow struct {
	ID          int64  `json:"id"`
	PathType    string `json:"path_type"`
	PathPattern string `json:"path_pattern"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

type DisguiseRow struct {
	ID           int64  `json:"id"`
	FromCategory string `json:"from_category"`
	ToExtension  string `json:"to_extension"`
	IsActive     bool   `json:"is_active"`
}
