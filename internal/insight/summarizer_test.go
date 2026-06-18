package insight

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSummarizerProviderDefaults(t *testing.T) {
	anthropic := NewSummarizer(nil, "anthropic-key", "", "", nil)
	if !anthropic.Enabled() {
		t.Fatal("anthropic summarizer should be enabled")
	}
	if anthropic.model != defaultModel {
		t.Fatalf("anthropic default model = %q, want %q", anthropic.model, defaultModel)
	}

	gemini := NewSummarizer(nil, "anthropic-key", "gemini-key", "claude-opus-4-8", nil)
	if !gemini.Enabled() {
		t.Fatal("gemini summarizer should be enabled")
	}
	if gemini.model != "gemini-flash-latest" {
		t.Fatalf("gemini model = %q, want gemini-flash-latest", gemini.model)
	}

	disabled := NewSummarizer(nil, "", "", "", nil)
	if disabled.Enabled() {
		t.Fatal("summarizer without keys should be disabled")
	}
}

func TestSummaryHandlerDisabled(t *testing.T) {
	handler := NewHandler(NewSummarizer(nil, "", "", "", nil), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/insight/summary?hours=24", nil)
	rec := httptest.NewRecorder()

	handler.Summary(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if body["error"] == "" {
		t.Fatal("expected error message")
	}
}
