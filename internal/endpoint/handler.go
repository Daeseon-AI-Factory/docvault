package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertEvaluator is called after storing an event to fire alert rules.
type AlertEvaluator interface {
	Evaluate(ctx context.Context, event *EndpointEvent)
}

type Handler struct {
	repo           *Repository
	db             *pgxpool.Pool
	psk            string
	alertEvaluator AlertEvaluator
	logger         *slog.Logger
}

func NewHandler(repo *Repository, db *pgxpool.Pool, psk string, alertEval AlertEvaluator, logger *slog.Logger) *Handler {
	return &Handler{
		repo:           repo,
		db:             db,
		psk:            psk,
		alertEvaluator: alertEval,
		logger:         logger,
	}
}

// lookupUserByHostname resolves hostname to user_id from endpoint_agents table.
func (h *Handler) lookupUserByHostname(ctx context.Context, hostname string) *int64 {
	var userID int64
	err := h.db.QueryRow(ctx,
		`SELECT user_id FROM endpoint_agents WHERE hostname = $1 AND is_active = true`, hostname,
	).Scan(&userID)
	if err != nil {
		return nil
	}
	return &userID
}

// buildHostnameMap builds a hostname→userID map for a batch of events.
func (h *Handler) buildHostnameMap(ctx context.Context, hostnames []string) map[string]int64 {
	m := make(map[string]int64)
	for _, hostname := range hostnames {
		if uid := h.lookupUserByHostname(ctx, hostname); uid != nil {
			m[hostname] = *uid
		}
	}
	return m
}

// ReceiveOsquery handles POST /api/events/osquery
func (h *Handler) ReceiveOsquery(w http.ResponseWriter, r *http.Request) {
	if h.psk != "" {
		token := r.Header.Get("X-Osquery-PSK")
		if token != h.psk {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	var batch OsqueryBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if len(batch.Results) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "received": 0})
		return
	}

	// Collect unique hostnames
	hostSet := make(map[string]bool)
	for _, r := range batch.Results {
		hostSet[r.HostIdentifier] = true
	}
	var hostnames []string
	for h := range hostSet {
		hostnames = append(hostnames, h)
	}

	hostnameMap := h.buildHostnameMap(r.Context(), hostnames)
	events := NormalizeOsqueryEvents(&batch, hostnameMap)

	if err := h.repo.InsertBatch(r.Context(), events); err != nil {
		h.logger.Error("receive osquery events", "error", err, "count", len(events))
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Evaluate alert rules against each event
	if h.alertEvaluator != nil {
		for _, event := range events {
			h.alertEvaluator.Evaluate(r.Context(), event)
		}
	}

	h.logger.Info("received osquery events", "count", len(events), "host", batch.Results[0].HostIdentifier)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"received": len(events),
	})
}

// ReceiveClipboard handles POST /api/events/clipboard
func (h *Handler) ReceiveClipboard(w http.ResponseWriter, r *http.Request) {
	if h.psk != "" {
		token := r.Header.Get("X-Agent-PSK")
		if token != h.psk {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	var ce ClipboardEvent
	if err := json.NewDecoder(r.Body).Decode(&ce); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	hostnameMap := h.buildHostnameMap(r.Context(), []string{ce.Hostname})
	event := NormalizeClipboardEvent(&ce, hostnameMap)

	if err := h.repo.Insert(r.Context(), event); err != nil {
		h.logger.Error("receive clipboard event", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Evaluate alert rules
	if h.alertEvaluator != nil {
		h.alertEvaluator.Evaluate(r.Context(), event)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

// Enroll handles POST /api/enroll — registers an agent's hostname-to-user mapping.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	if h.psk != "" {
		token := r.Header.Get("X-Agent-PSK")
		if token == "" {
			token = r.Header.Get("X-Osquery-PSK")
		}
		if token != h.psk {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		Source   string `json:"source"` // "osquery" or "clipboard"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Hostname == "" {
		http.Error(w, `{"error":"hostname is required"}`, http.StatusBadRequest)
		return
	}
	if req.Source == "" {
		req.Source = "osquery"
	}

	// Look up user by username
	var userID *int64
	if req.Username != "" {
		var uid int64
		err := h.db.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, req.Username,
		).Scan(&uid)
		if err == nil {
			userID = &uid
		}
	}

	// Upsert endpoint_agents
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO endpoint_agents (hostname, user_id, source, last_checkin)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (hostname, source) DO UPDATE SET user_id = $2, last_checkin = NOW(), is_active = true`,
		req.Hostname, userID, req.Source,
	)
	if err != nil {
		h.logger.Error("enroll agent", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	h.logger.Info("agent enrolled", "hostname", req.Hostname, "source", req.Source, "user_id", userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "enrolled",
		"hostname": req.Hostname,
	})
}

// AgentConfig handles POST /api/config — serves osquery config to enrolled agents.
func (h *Handler) AgentConfig(w http.ResponseWriter, r *http.Request) {
	if h.psk != "" {
		token := r.Header.Get("X-Osquery-PSK")
		if token != h.psk {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	// Return a minimal valid osquery config
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"schedule":{"file_events":{"query":"SELECT * FROM file_events;","interval":30}},"node_invalid":false}`)
}

// SearchEvents handles GET /api/events/search
func (h *Handler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	params := SearchParams{}

	if v := r.URL.Query().Get("user_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			params.UserID = &id
		}
	}
	if v := r.URL.Query().Get("hostname"); v != "" {
		params.Hostname = &v
	}
	if v := r.URL.Query().Get("event_type"); v != "" {
		et := EventType(v)
		params.EventType = &et
	}
	if v := r.URL.Query().Get("file_name"); v != "" {
		params.FileName = &v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		params.Source = &v
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
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			params.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			params.Offset = n
		}
	}

	events, err := h.repo.Search(r.Context(), params)
	if err != nil {
		h.logger.Error("search events", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
}

// UnifiedTimeline handles GET /api/timeline/{userID}
func (h *Handler) UnifiedTimeline(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "userID")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid user ID"}`, http.StatusBadRequest)
		return
	}

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

	entries, err := h.repo.UnifiedTimeline(r.Context(), userID, limit, offset)
	if err != nil {
		h.logger.Error("unified timeline", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"timeline": entries})
}
