package alert

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonAIFactory/Product024_JasonDRM/internal/auth"
)

type Handler struct {
	repo     *Repository
	logger   *slog.Logger
	notifier *Notifier
	pool     *pgxpool.Pool
}

func NewHandler(repo *Repository, logger *slog.Logger) *Handler {
	return &Handler{repo: repo, logger: logger}
}

// SetDigest wires the notifier + pool so the daily digest can be sent on demand.
func (h *Handler) SetDigest(notifier *Notifier, pool *pgxpool.Pool) {
	h.notifier = notifier
	h.pool = pool
}

// SendDigestNow (POST /api/alerts/digest-now, admin-only) emails the daily
// security digest immediately — for testing the email pipeline and for an
// on-demand "send me the summary now".
func (h *Handler) SendDigestNow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.notifier == nil || !h.notifier.email.enabled() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "이메일이 설정되지 않았습니다 (DOCVAULT_SMTP_HOST/USER/PASS, DOCVAULT_ALERT_EMAIL 필요)."})
		return
	}
	if err := h.notifier.SendDailyDigest(r.Context(), h.pool, h.repo); err != nil {
		h.logger.Error("send digest now", "error", err)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "발송 실패: " + err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sent", "to": h.notifier.email.To})
}

// ListAlerts handles GET /api/alerts?unacked=true&limit=&offset=
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	unackedOnly := r.URL.Query().Get("unacked") == "true"

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

	alerts, err := h.repo.ListAlerts(r.Context(), unackedOnly, limit, offset)
	if err != nil {
		h.logger.Error("list alerts", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
	})
}

// Acknowledge handles POST /api/alerts/{alertID}/acknowledge
func (h *Handler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	alertIDStr := chi.URLParam(r, "alertID")
	alertID, err := strconv.ParseInt(alertIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid alert ID"}`, http.StatusBadRequest)
		return
	}

	if err := h.repo.Acknowledge(r.Context(), alertID, user.ID); err != nil {
		h.logger.Error("acknowledge alert", "error", err)
		http.Error(w, `{"error":"alert not found or already acknowledged"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "alert acknowledged",
	})
}

// ListRules handles GET /api/alerts/rules
func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.repo.ListRules(r.Context(), false)
	if err != nil {
		h.logger.Error("list rules", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
	})
}

type createRuleRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	EventType   string          `json:"event_type"`
	Condition   json.RawMessage `json:"condition"`
	Severity    Severity        `json:"severity"`
}

// CreateRule handles POST /api/alerts/rules
func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req createRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.EventType == "" {
		http.Error(w, `{"error":"name and event_type are required"}`, http.StatusBadRequest)
		return
	}
	if req.Severity == "" {
		req.Severity = SeverityMedium
	}

	rule := &AlertRule{
		Name:        req.Name,
		Description: req.Description,
		EventType:   req.EventType,
		Condition:   req.Condition,
		Severity:    req.Severity,
		CreatedBy:   user.ID,
	}

	if err := h.repo.CreateRule(r.Context(), rule); err != nil {
		h.logger.Error("create rule", "error", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}
