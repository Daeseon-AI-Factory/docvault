package insight

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Handler exposes the AI summary over HTTP.
type Handler struct {
	summarizer *Summarizer
	logger     *slog.Logger
}

func NewHandler(s *Summarizer, logger *slog.Logger) *Handler {
	return &Handler{summarizer: s, logger: logger}
}

// Summary handles GET /api/insight/summary?hours=24
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.summarizer == nil || !h.summarizer.Enabled() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "AI summary is not configured. Set DOCVAULT_ANTHROPIC_API_KEY on the server to enable it.",
		})
		return
	}

	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	sum, err := h.summarizer.Generate(r.Context(), hours)
	if err != nil {
		h.logger.Error("ai summary", "error", err)
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to generate summary"})
		return
	}

	json.NewEncoder(w).Encode(sum)
}
