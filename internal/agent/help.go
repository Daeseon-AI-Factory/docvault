package agent

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed help_kb.md
var helpKB string

// helpTools gives the assistant a doc-grounded "how-to" capability so it can
// guide a non-technical admin through using the product. This is lightweight RAG:
// the help_docs tool is the retrieval step over a small, curated usage guide
// (help_kb.md); the model then answers grounded ONLY in the returned text. At this
// KB size, returning the whole guide is the most accurate option (no retrieval
// miss, and the model handles paraphrase). Upgrade to ranked/embedding retrieval
// only if the KB outgrows the context window.
func helpTools() []Tool {
	return []Tool{
		{
			Name:        "help_docs",
			Description: "사용법/설치/기능/'어떻게 ~해?'/'이거 뭐야?' 같은 제품 사용 질문에 답하기 전에 공식 사용설명서를 가져온다. 반드시 이 결과 텍스트에만 근거해 답하고, 없으면 모른다고 한다.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "사용자의 사용법 질문 (예: '직원 컴퓨터에 어떻게 설치해?')"},
				},
				"required": []any{"query"},
			},
			Run: func(_ context.Context, _ *pgxpool.Pool, args map[string]any) (string, error) {
				query, _ := args["query"].(string)
				return fmt.Sprintf(
					"[공식 사용설명서 — 아래 내용에만 근거해 \"%s\"에 단계별로 아주 쉬운 한국어로 답하세요. 설명서에 없는 내용은 지어내지 마세요.]\n\n%s",
					query, helpKB), nil
			},
		},
	}
}
