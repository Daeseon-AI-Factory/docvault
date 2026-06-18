package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type providerStep struct {
	text  string
	calls []ToolCall
	err   error
}

type scriptedProvider struct {
	steps []providerStep
	idx   int
}

func (p *scriptedProvider) Chat(ctx context.Context, system string, msgs []Msg, tools []Tool) (string, []ToolCall, error) {
	if p.idx >= len(p.steps) {
		return "", nil, errors.New("unexpected provider call")
	}
	step := p.steps[p.idx]
	p.idx++
	return step.text, step.calls, step.err
}

func (p *scriptedProvider) Name() string { return "scripted" }

func testEngine(provider Provider, tools []Tool) *Engine {
	byName := make(map[string]Tool, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	return &Engine{provider: provider, tools: tools, byName: byName}
}

func TestMutatingToolRequiresServerConfirmation(t *testing.T) {
	ran := false
	tool := Tool{
		Name:                 "mutate_state",
		RequiresConfirmation: true,
		Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
			ran = true
			return `{"ok":true}`, nil
		},
	}
	provider := &scriptedProvider{steps: []providerStep{{
		calls: []ToolCall{{ID: "call-1", Name: "mutate_state", Args: map[string]any{"target": "pc-1"}}},
	}}}
	engine := testEngine(provider, []Tool{tool})

	answer, history, err := engine.Chat(context.Background(), 7, "최근 이벤트 보고 필요하면 처리해줘", nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if ran {
		t.Fatal("mutating tool ran without explicit confirmation")
	}
	if !strings.Contains(answer, "실행 승인") {
		t.Fatalf("answer = %q, want confirmation instructions", answer)
	}
	if len(history) != 2 || history[1].Role != "assistant" {
		t.Fatalf("history = %#v, want user + assistant confirmation", history)
	}
}

func TestMutatingToolRunsAfterPendingConfirmation(t *testing.T) {
	ran := false
	tool := Tool{
		Name:                 "mutate_state",
		RequiresConfirmation: true,
		Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
			ran = true
			if args["target"] != "pc-1" {
				t.Fatalf("args[target] = %v", args["target"])
			}
			return `{"ok":true}`, nil
		},
	}
	provider := &scriptedProvider{steps: []providerStep{
		{calls: []ToolCall{{ID: "call-1", Name: "mutate_state", Args: map[string]any{"target": "pc-1"}}}},
		{text: "처리했습니다."},
	}}
	engine := testEngine(provider, []Tool{tool})
	history := []Msg{{Role: "assistant", Content: confirmationPrompt([]ToolCall{{
		ID: "call-1", Name: "mutate_state", Args: map[string]any{"target": "pc-1"},
	}})}}

	answer, _, err := engine.Chat(context.Background(), 7, "실행 승인", history)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if !ran {
		t.Fatal("mutating tool did not run after pending confirmation")
	}
	if answer != "처리했습니다." {
		t.Fatalf("answer = %q", answer)
	}
}

func TestReadToolRunsWithoutConfirmation(t *testing.T) {
	ran := false
	tool := Tool{
		Name: "read_state",
		Run: func(ctx context.Context, db *pgxpool.Pool, args map[string]any) (string, error) {
			ran = true
			return `{"count":1}`, nil
		},
	}
	provider := &scriptedProvider{steps: []providerStep{
		{calls: []ToolCall{{ID: "call-1", Name: "read_state"}}},
		{text: "1건입니다."},
	}}
	engine := testEngine(provider, []Tool{tool})

	answer, _, err := engine.Chat(context.Background(), 7, "최근 상태 알려줘", nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if !ran {
		t.Fatal("read tool did not run")
	}
	if answer != "1건입니다." {
		t.Fatalf("answer = %q", answer)
	}
}
