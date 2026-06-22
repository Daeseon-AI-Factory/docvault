package agent

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestGeminiToolUseLive exercises the exact path that the thoughtSignature fix
// covers: a tool call, then a second turn that REPLAYS that functionCall (where
// Gemini previously returned "400: Function call is missing a thought_signature").
// Network + key required, so it skips unless DOCVAULT_GEMINI_API_KEY is set
// (skipped in CI). Re-run when Google's Gemini capacity has recovered:
//
//	DOCVAULT_GEMINI_API_KEY=... go test -run TestGeminiToolUseLive -v ./internal/agent
func TestGeminiToolUseLive(t *testing.T) {
	key := os.Getenv("DOCVAULT_GEMINI_API_KEY")
	if key == "" {
		t.Skip("DOCVAULT_GEMINI_API_KEY not set — skipping live Gemini test")
	}
	model := os.Getenv("DOCVAULT_AI_MODEL")
	if !strings.HasPrefix(model, "gemini") {
		model = "gemini-flash-latest"
	}
	p := NewProvider("", key, "gemini", model)
	if p == nil {
		t.Fatal("nil provider")
	}

	tools := []Tool{{
		Name:        "get_count",
		Description: "Returns the current event count as a number.",
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
	}}
	ctx := context.Background()

	// Turn 1: prompt the model to call the tool.
	_, calls, err := p.Chat(ctx, "You are a test assistant. When asked, call the provided tool.",
		[]Msg{{Role: "user", Content: "get_count 도구를 호출해서 현재 개수를 알려줘."}}, tools)
	if err != nil {
		t.Fatalf("turn 1 failed (likely Google capacity if 503): %v", err)
	}
	if len(calls) == 0 {
		t.Skip("model did not call the tool on turn 1 — cannot exercise signature replay")
	}
	t.Logf("turn 1 ok: %d call(s), sig present=%v", len(calls), calls[0].Sig != "")

	// Turn 2: replay the functionCall + a tool response. THIS is the line that
	// returned 400 before the thoughtSignature fix.
	msgs := []Msg{
		{Role: "user", Content: "get_count 도구를 호출해서 현재 개수를 알려줘."},
		{Role: "assistant", ToolCalls: calls},
		{Role: "tool", Name: calls[0].Name, ToolCallID: calls[0].ID, Content: "42"},
	}
	answer, _, err := p.Chat(ctx, "You are a test assistant.", msgs, tools)
	if err != nil {
		if strings.Contains(err.Error(), "thought_signature") {
			t.Fatalf("FIX FAILED — signature still missing: %v", err)
		}
		t.Fatalf("turn 2 failed (likely Google capacity if 503): %v", err)
	}
	t.Logf("PASS: tool-use replay succeeded, answer=%q", answer)
}
