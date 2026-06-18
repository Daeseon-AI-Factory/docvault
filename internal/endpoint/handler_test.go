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
		{"heartbeat", h.ReceiveHeartbeat, `{}`},
		{"self-test", h.ReceiveSelfTest, `{}`},
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
		{"heartbeat", h.ReceiveHeartbeat, "X-Agent-PSK", `{}`},
		{"self-test", h.ReceiveSelfTest, "X-Agent-PSK", `{}`},
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

func TestEndpointUsernameCandidate(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alice", "alice"},
		{`ACME\alice`, "alice"},
		{"ACME/bob", "bob"},
		{"  기민철  ", "기민철"},
	}
	for _, tt := range tests {
		if got := endpointUsernameCandidate(tt.in); got != tt.want {
			t.Fatalf("endpointUsernameCandidate(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsAutoAssignableEndpointUsername(t *testing.T) {
	yes := []string{"alice", "기민철", "runneradmin"}
	for _, username := range yes {
		if !isAutoAssignableEndpointUsername(username) {
			t.Fatalf("%q should be auto-assignable", username)
		}
	}

	no := []string{"", "DESKTOP-MLTM9DR$", "기민철$", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
	for _, username := range no {
		if isAutoAssignableEndpointUsername(username) {
			t.Fatalf("%q should not be auto-assignable", username)
		}
	}
}

func TestAutoEndpointEmailIsStableAndInternal(t *testing.T) {
	a := autoEndpointEmail("Alice")
	b := autoEndpointEmail("alice")
	if a != b {
		t.Fatalf("autoEndpointEmail should be case-insensitive stable: %q != %q", a, b)
	}
	if !strings.HasPrefix(a, "endpoint-") || !strings.HasSuffix(a, "@docvault.local") {
		t.Fatalf("autoEndpointEmail(%q) = %q", "alice", a)
	}
}
