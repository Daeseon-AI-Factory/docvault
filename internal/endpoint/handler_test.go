package endpoint

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentEndpointsFailClosedWhenPSKIsMissing(t *testing.T) {
	h := NewHandler(nil, nil, "", nil, nil)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		body    string
	}{
		{"osquery", h.ReceiveOsquery, `{"results":[]}`},
		{"clipboard", h.ReceiveClipboard, `{}`},
		{"enroll", h.Enroll, `{}`},
		{"config", h.AgentConfig, `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/"+tt.name, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			tt.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestAgentEndpointsRejectWrongPSKBeforeProcessing(t *testing.T) {
	h := NewHandler(nil, nil, "expected-psk", nil, nil)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		header  string
		body    string
	}{
		{"osquery", h.ReceiveOsquery, "X-Osquery-PSK", `{"results":[]}`},
		{"clipboard", h.ReceiveClipboard, "X-Agent-PSK", `{}`},
		{"enroll", h.Enroll, "X-Agent-PSK", `{}`},
		{"config", h.AgentConfig, "X-Osquery-PSK", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/"+tt.name, strings.NewReader(tt.body))
			req.Header.Set(tt.header, "wrong-psk")
			rec := httptest.NewRecorder()

			tt.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}
