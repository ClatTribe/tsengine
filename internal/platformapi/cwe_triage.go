package platformapi

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cweattrib"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// defaultCWEAttributionMax bounds the model spend per scan. The tier is meant to be cheap; a scan
// emitting thousands of unclassified findings must not become an unbounded inference bill. Findings
// past the cap keep the state they have today — unclassified — rather than a guessed one.
const defaultCWEAttributionMax = 25

// CWEAttributor returns the runner seam that fills a missing CWE before the L1.5 chain runs.
//
// THE GAP (§8): the crosswalk keys on CWE and compliance.Apply returns early without one, so a
// finding whose scanner never set one gets NO control mapping at all — and an empty annotation looks
// exactly like a CWE with no control nexus. The KEV backfill closed that for CVE-bearing findings.
// This is the rest: grype and osv-scanner never set a CWE, only trivy does.
//
// internal/cweattrib is the analyser for it and had NO caller — Attribute and Fill were reachable
// only from their own tests, so a measured, carefully-constrained triage tier sat inert while the
// mapping it exists to enable stayed empty.
//
// GATED THREE WAYS, all failing toward doing nothing:
//   - no tenant model → Attribute returns "attribution disabled" and the findings pass through. This
//     inherits the plan entitlement: resolveAgentLLM is the economic gate, so a Free workspace spends
//     nothing here.
//   - Allowed is the crosswalk's OWN key set, so a class we cannot map is discarded rather than
//     annotated. An unmappable CWE would add an unusable annotation with a veneer of authority.
//   - bounded per scan by TSENGINE_CWE_ATTRIBUTION_MAX (default 25); 0 or negative disables it.
func (d Deps) CWEAttributor() func(ctx context.Context, tenantID string, fs []types.Finding) []types.Finding {
	allowed := hooks.NewCompliance().MappedCWEs()
	return func(ctx context.Context, tenantID string, fs []types.Finding) []types.Finding {
		max := cweAttributionMax()
		if max <= 0 || len(fs) == 0 || len(allowed) == 0 {
			return fs
		}
		if d.Store == nil {
			// resolveAgentLLM reads the tenant to apply the AI-mode and plan gates, so without a
			// store there is no gate to apply — and this seam runs on every scan, where the correct
			// behaviour under any doubt is to do nothing rather than to reason ungated.
			return fs
		}
		llm := d.resolveAgentLLM(ctx, tenantID)
		if llm == nil {
			return fs // no model: the findings keep the state they already have
		}
		out, _ := cweattrib.Attributor{LLM: llm, Allowed: allowed}.Fill(ctx, fs, max)
		return out
	}
}

func cweAttributionMax() int {
	raw := strings.TrimSpace(os.Getenv("TSENGINE_CWE_ATTRIBUTION_MAX"))
	if raw == "" {
		return defaultCWEAttributionMax
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultCWEAttributionMax
	}
	return n
}

// attributeWith is the test seam: the same call the runner seam makes, without the Deps plumbing, so
// a test exercises the real Attributor and the real crosswalk key set rather than a reimplementation.
func attributeWith(llm cweattrib.LLM, fs []types.Finding, max int) ([]types.Finding, []cweattrib.Result) {
	return cweattrib.Attributor{LLM: llm, Allowed: hooks.NewCompliance().MappedCWEs()}.Fill(
		context.Background(), fs, max)
}
