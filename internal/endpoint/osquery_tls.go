package endpoint

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// --- osquery TLS server protocol ---
//
// Implements the three endpoints an osquery agent (config_plugin=tls,
// logger_plugin=tls) calls: enroll, config, and logger. Authentication follows
// the osquery model: a shared enroll_secret is exchanged for a per-node
// node_key, which the node then presents on every config/log request. This is
// distinct from the clipboard agent, which uses the X-Agent-PSK header.

type osqueryEnrollRequest struct {
	EnrollSecret   string          `json:"enroll_secret"`
	HostIdentifier string          `json:"host_identifier"`
	HostDetails    json.RawMessage `json:"host_details,omitempty"`
}

// OsqueryEnroll handles POST /api/osquery/enroll.
func (h *Handler) OsqueryEnroll(w http.ResponseWriter, r *http.Request) {
	var req osqueryEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNodeInvalid(w)
		return
	}

	// The enroll secret is the shared DOCVAULT_OSQUERY_PSK. Fail closed if unset.
	if h.psk == "" || subtle.ConstantTimeCompare([]byte(req.EnrollSecret), []byte(h.psk)) != 1 {
		writeNodeInvalid(w)
		return
	}
	if req.HostIdentifier == "" {
		writeNodeInvalid(w)
		return
	}

	nodeKey, err := generateNodeKey()
	if err != nil {
		h.logger.Error("osquery enroll: generate node key", "error", err)
		writeNodeInvalid(w)
		return
	}

	_, err = h.db.Exec(r.Context(),
		`INSERT INTO endpoint_agents (hostname, source, node_key, last_ip, last_checkin, is_active)
		 VALUES ($1, 'osquery', $2, $3, NOW(), true)
		 ON CONFLICT (hostname, source)
		 DO UPDATE SET node_key = $2,
		               last_ip = COALESCE(NULLIF($3, ''), endpoint_agents.last_ip),
		               last_checkin = NOW(),
		               is_active = true`,
		req.HostIdentifier, nodeKey, clientIP(r))
	if err != nil {
		h.logger.Error("osquery enroll: upsert", "error", err)
		writeNodeInvalid(w)
		return
	}

	h.logger.Info("osquery node enrolled", "hostname", req.HostIdentifier)
	writeJSONResponse(w, map[string]interface{}{"node_key": nodeKey, "node_invalid": false})
}

type osqueryNodeRequest struct {
	NodeKey string `json:"node_key"`
}

// OsqueryConfig handles POST /api/osquery/config.
func (h *Handler) OsqueryConfig(w http.ResponseWriter, r *http.Request) {
	var req osqueryNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNodeInvalid(w)
		return
	}
	if _, _, ok := h.nodeFromKey(r.Context(), req.NodeKey); !ok {
		writeNodeInvalid(w)
		return
	}
	// buildOsqueryConfig already includes "node_invalid": false.
	writeJSONResponse(w, h.buildOsqueryConfig(r.Context()))
}

type osqueryLogRequest struct {
	NodeKey string            `json:"node_key"`
	LogType string            `json:"log_type"`
	Data    []json.RawMessage `json:"data"`
}

// OsqueryLog handles POST /api/osquery/log.
func (h *Handler) OsqueryLog(w http.ResponseWriter, r *http.Request) {
	var req osqueryLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNodeInvalid(w)
		return
	}

	hostname, _, ok := h.nodeFromKey(r.Context(), req.NodeKey)
	if !ok {
		writeNodeInvalid(w)
		return
	}

	// Only "result" logs carry scheduled-query rows; "status" logs are
	// operational messages we simply acknowledge.
	if req.LogType == "result" {
		results := make([]OsqueryResult, 0, len(req.Data))
		for _, raw := range req.Data {
			var res OsqueryResult
			if err := json.Unmarshal(raw, &res); err != nil {
				continue
			}
			if res.HostIdentifier == "" {
				res.HostIdentifier = hostname
			}
			results = append(results, res)
		}
		if len(results) > 0 {
			if _, err := h.processOsqueryBatch(r.Context(), &OsqueryBatch{NodeKey: req.NodeKey, Results: results}); err != nil {
				// Report the node as still valid so osquery retries the buffered logs.
				http.Error(w, `{"node_invalid": false}`, http.StatusInternalServerError)
				return
			}
		}
	}

	writeJSONResponse(w, map[string]interface{}{"node_invalid": false})
}

// nodeFromKey resolves an enrolled node_key to its hostname and user mapping.
func (h *Handler) nodeFromKey(ctx context.Context, nodeKey string) (string, *int64, bool) {
	if nodeKey == "" {
		return "", nil, false
	}
	var hostname string
	var userID *int64
	err := h.db.QueryRow(ctx,
		`SELECT hostname, user_id FROM endpoint_agents WHERE node_key = $1 AND is_active = true`,
		nodeKey,
	).Scan(&hostname, &userID)
	if err != nil {
		return "", nil, false
	}
	if _, err := h.db.Exec(ctx,
		`UPDATE endpoint_agents SET last_checkin = NOW(), is_active = true WHERE node_key = $1`,
		nodeKey,
	); err != nil {
		if h.logger != nil {
			h.logger.Warn("osquery touch node", "hostname", hostname, "error", err)
		}
	}
	return hostname, userID, true
}

func generateNodeKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeNodeInvalid(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"node_invalid": true}`))
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
