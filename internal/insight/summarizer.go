// Package insight turns recent endpoint activity into a short natural-language
// security briefing using the Claude (Anthropic) Messages API. It is an
// optional layer on top of the rule-based alert engine — disabled unless an API
// key is configured.
package insight

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
	defaultModel     = "claude-opus-4-8" // override with DOCVAULT_AI_MODEL (e.g. claude-haiku-4-5 = cheapest/fastest)
	maxSummaryTokens = 1024
)

// Summarizer builds a digest of recent activity and asks Claude to summarize it.
type Summarizer struct {
	db        *pgxpool.Pool
	apiKey    string // Anthropic
	geminiKey string // Google Gemini (takes precedence if set)
	model     string
	client    *http.Client
	logger    *slog.Logger
}

func NewSummarizer(db *pgxpool.Pool, anthropicKey, geminiKey, model string, logger *slog.Logger) *Summarizer {
	s := &Summarizer{
		db:        db,
		apiKey:    anthropicKey,
		geminiKey: geminiKey,
		model:     model,
		client:    &http.Client{Timeout: 60 * time.Second},
		logger:    logger,
	}
	switch {
	case geminiKey != "":
		// Using Gemini — pick a Gemini model unless one was explicitly configured.
		if !strings.HasPrefix(model, "gemini") {
			s.model = "gemini-flash-latest" // alias → always current flash (won't get retired)
		}
	case model == "":
		s.model = defaultModel
	}
	return s
}

// Enabled reports whether any AI provider key is configured.
func (s *Summarizer) Enabled() bool { return s.apiKey != "" || s.geminiKey != "" }

// Summary is the result returned to callers.
type Summary struct {
	Text        string `json:"text"`
	Model       string `json:"model"`
	WindowHours int    `json:"window_hours"`
	EventCount  int    `json:"event_count"`
	GeneratedAt string `json:"generated_at"`
}

// Generate digests the last `hours` of activity and asks Claude to summarize it.
func (s *Summarizer) Generate(ctx context.Context, hours int) (*Summary, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("AI summary is not configured (set DOCVAULT_ANTHROPIC_API_KEY)")
	}
	if hours <= 0 {
		hours = 24
	}

	digest, count, err := s.buildDigest(ctx, hours)
	if err != nil {
		return nil, fmt.Errorf("build digest: %w", err)
	}

	var text string
	if s.geminiKey != "" {
		text, err = s.callGemini(ctx, digest)
	} else {
		text, err = s.callClaude(ctx, digest)
	}
	if err != nil {
		return nil, err
	}

	return &Summary{
		Text:        text,
		Model:       s.model,
		WindowHours: hours,
		EventCount:  count,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// buildDigest compiles a compact, factual text digest from the DB so the model
// only sees a summary, not raw rows — keeps token cost and latency low.
func (s *Summarizer) buildDigest(ctx context.Context, hours int) (string, int, error) {
	var b strings.Builder
	total := 0

	fmt.Fprintf(&b, "Endpoint activity in the last %d hours.\n\nEvent counts by type:\n", hours)
	rows, err := s.db.Query(ctx, `
		SELECT event_type, COUNT(*) FROM endpoint_events
		WHERE event_time > NOW() - make_interval(hours => $1)
		GROUP BY event_type ORDER BY COUNT(*) DESC`, hours)
	if err != nil {
		return "", 0, fmt.Errorf("count events: %w", err)
	}
	for rows.Next() {
		var et string
		var c int
		if err := rows.Scan(&et, &c); err != nil {
			rows.Close()
			return "", 0, err
		}
		total += c
		fmt.Fprintf(&b, "- %s: %d\n", et, c)
	}
	rows.Close()
	if total == 0 {
		b.WriteString("(no events)\n")
	}

	b.WriteString("\nMost recent notable events (time | host | type | file | process):\n")
	nrows, err := s.db.Query(ctx, `
		SELECT event_time, hostname, event_type, COALESCE(file_name,''), COALESCE(process_name,'')
		FROM endpoint_events
		WHERE event_time > NOW() - make_interval(hours => $1)
		ORDER BY event_time DESC LIMIT 25`, hours)
	if err != nil {
		return "", 0, fmt.Errorf("recent events: %w", err)
	}
	for nrows.Next() {
		var t time.Time
		var host, et, fn, pn string
		if err := nrows.Scan(&t, &host, &et, &fn, &pn); err != nil {
			nrows.Close()
			return "", 0, err
		}
		fmt.Fprintf(&b, "- %s | %s | %s | %s | %s\n", t.Format(time.RFC3339), host, et, fn, pn)
	}
	nrows.Close()

	b.WriteString("\nUnacknowledged alerts (severity | message | time):\n")
	arows, err := s.db.Query(ctx, `
		SELECT severity, message, created_at FROM alerts
		WHERE is_acknowledged = false
		ORDER BY created_at DESC LIMIT 25`)
	if err != nil {
		b.WriteString("(alerts unavailable)\n")
	} else {
		any := false
		for arows.Next() {
			var sev, msg string
			var t time.Time
			if err := arows.Scan(&sev, &msg, &t); err == nil {
				any = true
				fmt.Fprintf(&b, "- [%s] %s (%s)\n", sev, msg, t.Format(time.RFC3339))
			}
		}
		arows.Close()
		if !any {
			b.WriteString("(none)\n")
		}
	}

	return b.String(), total, nil
}

// --- Anthropic Messages API (raw net/http, no SDK) ---

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

const summarySystemPrompt = "You are a security analyst for DocVault, a small-team insider-threat monitoring tool. " +
	"Given a factual digest of endpoint activity, write a concise briefing in Korean for a non-expert admin. " +
	"Start with one line: overall risk level (낮음 / 보통 / 높음). Then 3-6 short bullet points naming the riskiest " +
	"activity (which host, what happened) and what to check. Be specific and factual — do NOT invent events that are " +
	"not in the data. Respond only with the briefing: no preamble, no markdown headings."

func (s *Summarizer) callClaude(ctx context.Context, digest string) (string, error) {
	body, err := json.Marshal(messagesRequest{
		Model:     s.model,
		MaxTokens: maxSummaryTokens,
		System:    summarySystemPrompt,
		Messages:  []message{{Role: "user", Content: digest}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		text, retryable, err := s.doRequest(ctx, body)
		if err == nil {
			return text, nil
		}
		lastErr = err
		if !retryable || attempt == 3 {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return "", lastErr
}

func (s *Summarizer) doRequest(ctx context.Context, body []byte) (text string, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", s.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", true, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var parsed messagesResponse
	_ = json.Unmarshal(data, &parsed)

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(data))
		if parsed.Error != nil {
			msg = parsed.Error.Message
		}
		// 429 and 5xx are transient; everything else (bad key, bad request) is not.
		return "", resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
			fmt.Errorf("anthropic %d: %s", resp.StatusCode, msg)
	}

	var sb strings.Builder
	for _, blk := range parsed.Content {
		if blk.Type == "text" {
			sb.WriteString(blk.Text)
		}
	}
	out := strings.TrimSpace(sb.String())
	if out == "" {
		return "", false, fmt.Errorf("empty response (stop_reason=%s)", parsed.StopReason)
	}
	return out, false, nil
}

// --- Gemini (Google Generative Language) API, raw net/http ---

const geminiURL = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text string `json:"text"`
}
type geminiRequest struct {
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
	GenerationConfig  map[string]any  `json:"generationConfig,omitempty"`
}
type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *Summarizer) callGemini(ctx context.Context, digest string) (string, error) {
	body, err := json.Marshal(geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: summarySystemPrompt}}},
		Contents:          []geminiContent{{Role: "user", Parts: []geminiPart{{Text: digest}}}},
		GenerationConfig: map[string]any{
			"maxOutputTokens": maxSummaryTokens,
			"temperature":     0.3,
			"thinkingConfig":  map[string]any{"thinkingBudget": 0}, // off → direct briefing, no scratchpad leak
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal gemini request: %w", err)
	}
	url := fmt.Sprintf(geminiURL, s.model)

	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set("x-goog-api-key", s.geminiKey)

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("gemini request: %w", err)
		} else {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var parsed geminiResponse
			_ = json.Unmarshal(data, &parsed)
			if resp.StatusCode == http.StatusOK {
				var sb strings.Builder
				for _, c := range parsed.Candidates {
					for _, p := range c.Content.Parts {
						sb.WriteString(p.Text)
					}
				}
				if out := strings.TrimSpace(sb.String()); out != "" {
					return out, nil
				}
				return "", fmt.Errorf("empty gemini response")
			}
			msg := strings.TrimSpace(string(data))
			if parsed.Error != nil {
				msg = parsed.Error.Message
			}
			lastErr = fmt.Errorf("gemini %d: %s", resp.StatusCode, msg)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return "", lastErr // non-retryable (bad key / bad request)
			}
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return "", lastErr
}
