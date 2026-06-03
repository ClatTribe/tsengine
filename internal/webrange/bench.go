package webrange

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// RunAgainst runs the web agent against a served range and scores it vs the
// manifest. base is the served base URL (httptest server or a live address). If
// llm is nil, the deterministic Prober drives the loop (CI-safe, no API key); pass
// a real cloudengine.LLM (Gemini) to bench the actual brain.
func RunAgainst(ctx context.Context, llm cloudengine.LLM, rg *Range, base string, maxRequests int) (*webagent.Report, Score, error) {
	surface := rg.Surface()
	routes := make([]string, len(surface))
	for i, s := range surface {
		routes[i] = base + s
	}
	if llm == nil {
		llm = NewProber(routes)
	}
	if maxRequests <= 0 {
		maxRequests = len(routes)*len(classPayloads) + len(routes) + 20
	}
	cc := &webagent.Context{Target: base, Routes: routes}
	rep, err := webagent.Investigate(ctx, llm, cc, webagent.Options{
		MaxRequests: maxRequests, MaxIters: maxRequests + 30,
	})
	if err != nil {
		return nil, Score{}, err
	}
	return rep, ScoreReport(rep, rg.Manifest, base), nil
}
