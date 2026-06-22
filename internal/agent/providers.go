package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NewProvider selects a provider from configured keys. Precedence (when
// `provider` is empty): openai > gemini. Returns nil if no key is set.
func NewProvider(openaiKey, geminiKey, provider, model string) Provider {
	provider = strings.ToLower(strings.TrimSpace(provider))
	client := &http.Client{Timeout: 90 * time.Second}

	use := provider
	if use == "" {
		switch {
		case openaiKey != "":
			use = "openai"
		case geminiKey != "":
			use = "gemini"
		}
	}
	switch use {
	case "openai":
		if openaiKey == "" {
			return nil
		}
		m := model
		if !strings.HasPrefix(m, "gpt") && !strings.HasPrefix(m, "o") {
			m = "gpt-4o-mini"
		}
		return &OpenAIProvider{key: openaiKey, model: m, client: client}
	case "gemini":
		if geminiKey == "" {
			return nil
		}
		m := model
		if !strings.HasPrefix(m, "gemini") {
			m = "gemini-flash-latest"
		}
		return &GeminiProvider{key: geminiKey, model: m, client: client}
	}
	return nil
}

// ---------------- OpenAI (chat completions + tools) ----------------

type OpenAIProvider struct {
	key    string
	model  string
	client *http.Client
}

func (p *OpenAIProvider) Name() string { return "openai:" + p.model }

type oaFunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}
type oaTool struct {
	Type     string        `json:"type"`
	Function oaFunctionDef `json:"function"`
}
type oaFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
type oaToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function oaFunctionCall `json:"function"`
}
type oaMsg struct {
	Role       string       `json:"role"`
	Content    string       `json:"content,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}
type oaReq struct {
	Model    string   `json:"model"`
	Messages []oaMsg  `json:"messages"`
	Tools    []oaTool `json:"tools,omitempty"`
}
type oaResp struct {
	Choices []struct {
		Message struct {
			Content   string       `json:"content"`
			ToolCalls []oaToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *OpenAIProvider) Chat(ctx context.Context, system string, msgs []Msg, tools []Tool) (string, []ToolCall, error) {
	oamsgs := []oaMsg{{Role: "system", Content: system}}
	for _, m := range msgs {
		switch m.Role {
		case "user":
			oamsgs = append(oamsgs, oaMsg{Role: "user", Content: m.Content})
		case "assistant":
			om := oaMsg{Role: "assistant", Content: m.Content}
			for _, c := range m.ToolCalls {
				b, _ := json.Marshal(c.Args)
				om.ToolCalls = append(om.ToolCalls, oaToolCall{
					ID: c.ID, Type: "function",
					Function: oaFunctionCall{Name: c.Name, Arguments: string(b)},
				})
			}
			oamsgs = append(oamsgs, om)
		case "tool":
			oamsgs = append(oamsgs, oaMsg{Role: "tool", ToolCallID: m.ToolCallID, Content: m.Content})
		}
	}
	var oatools []oaTool
	for _, t := range tools {
		oatools = append(oatools, oaTool{Type: "function", Function: oaFunctionDef{
			Name: t.Name, Description: t.Description, Parameters: t.Parameters,
		}})
	}
	body, err := json.Marshal(oaReq{Model: p.model, Messages: oamsgs, Tools: oatools})
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.key)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var pr oaResp
	_ = json.Unmarshal(data, &pr)
	if resp.StatusCode != http.StatusOK {
		m := strings.TrimSpace(string(data))
		if pr.Error != nil {
			m = pr.Error.Message
		}
		return "", nil, fmt.Errorf("openai %d: %s", resp.StatusCode, m)
	}
	if len(pr.Choices) == 0 {
		return "", nil, fmt.Errorf("openai: empty choices")
	}
	mm := pr.Choices[0].Message
	if len(mm.ToolCalls) > 0 {
		var calls []ToolCall
		for _, tc := range mm.ToolCalls {
			args := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			calls = append(calls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Args: args})
		}
		return mm.Content, calls, nil
	}
	return mm.Content, nil, nil
}

// ---------------- Gemini (generateContent + functionDeclarations) ----------------

type GeminiProvider struct {
	key    string
	model  string
	client *http.Client
}

func (p *GeminiProvider) Name() string { return "gemini:" + p.model }

type gmPart struct {
	Text             string          `json:"text,omitempty"`
	FunctionCall     *gmFunctionCall `json:"functionCall,omitempty"`
	FunctionResponse *gmFunctionResp `json:"functionResponse,omitempty"`
	// ThoughtSignature is Gemini's opaque token attached to a functionCall part;
	// it MUST be echoed back when replaying the call, or Gemini returns 400.
	ThoughtSignature string `json:"thoughtSignature,omitempty"`
}
type gmFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
}
type gmFunctionResp struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}
type gmContent struct {
	Role  string   `json:"role,omitempty"`
	Parts []gmPart `json:"parts"`
}
type gmReq struct {
	SystemInstruction *gmContent       `json:"systemInstruction,omitempty"`
	Contents          []gmContent      `json:"contents"`
	Tools             []map[string]any `json:"tools,omitempty"`
	GenerationConfig  map[string]any   `json:"generationConfig,omitempty"`
}
type gmResp struct {
	Candidates []struct {
		Content gmContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *GeminiProvider) Chat(ctx context.Context, system string, msgs []Msg, tools []Tool) (string, []ToolCall, error) {
	var contents []gmContent
	for _, m := range msgs {
		switch m.Role {
		case "user":
			contents = append(contents, gmContent{Role: "user", Parts: []gmPart{{Text: m.Content}}})
		case "assistant":
			c := gmContent{Role: "model"}
			if m.Content != "" {
				c.Parts = append(c.Parts, gmPart{Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				c.Parts = append(c.Parts, gmPart{
					FunctionCall:     &gmFunctionCall{Name: tc.Name, Args: tc.Args},
					ThoughtSignature: tc.Sig, // echo Gemini's signature back, required for tool-use
				})
			}
			if len(c.Parts) == 0 {
				c.Parts = []gmPart{{Text: ""}}
			}
			contents = append(contents, c)
		case "tool":
			contents = append(contents, gmContent{Role: "user", Parts: []gmPart{{
				FunctionResponse: &gmFunctionResp{Name: m.Name, Response: map[string]any{"result": m.Content}},
			}}})
		}
	}
	var decls []map[string]any
	for _, t := range tools {
		decls = append(decls, map[string]any{"name": t.Name, "description": t.Description, "parameters": t.Parameters})
	}
	body, err := json.Marshal(gmReq{
		SystemInstruction: &gmContent{Parts: []gmPart{{Text: system}}},
		Contents:          contents,
		Tools:             []map[string]any{{"functionDeclarations": decls}},
		GenerationConfig:  map[string]any{"temperature": 0.2, "thinkingConfig": map[string]any{"thinkingBudget": 0}},
	})
	if err != nil {
		return "", nil, err
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", p.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-goog-api-key", p.key)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var pr gmResp
	_ = json.Unmarshal(data, &pr)
	if resp.StatusCode != http.StatusOK {
		m := strings.TrimSpace(string(data))
		if pr.Error != nil {
			m = pr.Error.Message
		}
		return "", nil, fmt.Errorf("gemini %d: %s", resp.StatusCode, m)
	}
	if len(pr.Candidates) == 0 {
		return "", nil, fmt.Errorf("gemini: empty candidates")
	}
	var text strings.Builder
	var calls []ToolCall
	for _, part := range pr.Candidates[0].Content.Parts {
		if part.FunctionCall != nil {
			calls = append(calls, ToolCall{ID: part.FunctionCall.Name, Name: part.FunctionCall.Name, Args: part.FunctionCall.Args, Sig: part.ThoughtSignature})
		} else if part.Text != "" {
			text.WriteString(part.Text)
		}
	}
	return strings.TrimSpace(text.String()), calls, nil
}
