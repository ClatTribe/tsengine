package l2

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// reportTools are the L2 COMMIT tools — the persistent side-effects (§2.7):
// authoring a developer-facing vulnerability report, updating one, and
// recording a durable hypothesis. These are the only place the Lead's
// reasoning becomes durable crystal memory; the reasoning itself rides as
// tool PARAMETERS (reasoning-as-parameters), never as a `think` scratchpad.
//
// Eager-emit: create_vulnerability_report is available in EVERY phase (no
// gate) so the Lead commits a report the moment it's confident, rather than
// hoarding findings until a terminal flush (strix's "lost the finding when
// the run timed out" failure). The only terminal gate is finish_scan.
func reportTools(d Deps) Catalog {
	// Grounding set: a report may only cite L1 findings that actually exist.
	// This enforces "never invent" (the prompt rule) + §2.2 "L2 cannot
	// translate findings L1 didn't surface" at the TOOL boundary, not just by
	// asking nicely in the prompt.
	known := make(map[string]bool, len(d.L1Findings))
	for _, f := range d.L1Findings {
		known[f.ID] = true
	}

	return Catalog{
		{
			Schema: ToolSchema{
				Name: "create_vulnerability_report",
				Description: "Emit a developer/PM-facing vulnerability report grounded in one or more L1 findings. " +
					"Call it as soon as you're confident (eager-emit) — don't wait for the report phase. " +
					"All of your analysis rides here as parameters: the kill-chain, the plain-English explanation, the fix.",
				Params: obj(map[string]any{
					"title":                str("short title, e.g. 'Account takeover via SQLi + weak session'"),
					"severity":             enumStr("customer-facing severity (your judgment, may differ from the raw L1 severity)", "critical", "high", "medium", "low", "info"),
					"evidence_finding_ids": strArr("L1 finding ids this report rests on (≥1, must exist) — your evidence"),
					"kill_chain":           str("attack-chain narrative: how an attacker reaches and exploits this, step by step"),
					"plain_english":        str("explanation for a non-security reader (developer / PM)"),
					"remediation":          str("prioritized fix guidance / patch direction"),
					"cwe":                  strArr("optional CWE ids, e.g. CWE-89"),
				}, "title", "severity", "evidence_finding_ids", "plain_english"),
			},
			Handler: func(_ context.Context, args map[string]any, st *State) (ToolResult, error) {
				sev := types.Severity(strings.ToLower(argStr(args, "severity")))
				if !sev.Valid() {
					return ToolResult{Err: true, Content: "severity must be one of: critical, high, medium, low, info"}, nil
				}
				evidence := argStrList(args, "evidence_finding_ids")
				if len(evidence) == 0 {
					return ToolResult{Err: true, Content: "evidence_finding_ids is required — a report must cite the L1 finding(s) it rests on (never invent a vulnerability)"}, nil
				}
				for _, id := range evidence {
					if !known[id] {
						return ToolResult{Err: true, Content: fmt.Sprintf("no L1 finding with id %q — cite only finding ids from the digest (use get_finding to inspect them)", id)}, nil
					}
				}
				id := fmt.Sprintf("l2-%03d", len(st.Findings)+1)
				st.Findings = append(st.Findings, types.Finding{
					ID:              id,
					Tool:            "l2",
					Severity:        sev,
					Title:           argStr(args, "title"),
					CWE:             argStrList(args, "cwe"),
					Description:     argStr(args, "plain_english"),
					DiscoveryMethod: &types.DiscoveryMethod{Primary: "l2"},
					L2: &types.L2Report{
						EvidenceIDs:  evidence,
						KillChain:    argStr(args, "kill_chain"),
						PlainEnglish: argStr(args, "plain_english"),
						Remediation:  argStr(args, "remediation"),
						// Eager-emit at pattern_match strength; update_finding
						// upgrades to verified once independent methods confirm
						// it (L2-4 discipline).
						Verification: types.VerificationPatternMatch,
					},
				})
				return ToolResult{Content: fmt.Sprintf("emitted %s (%s) citing %s", id, sev, strings.Join(evidence, ", "))}, nil
			},
		},
		{
			Schema: ToolSchema{
				Name: "update_finding",
				Description: "Revise an L2 report you already emitted (by its l2-NNN id): change severity, refine the narrative, " +
					"or record verification progress. Use it after probing/verifying — don't emit a duplicate report.",
				Params: obj(map[string]any{
					"id":            str("the L2 report id, e.g. l2-001"),
					"severity":      enumStr("revised severity", "critical", "high", "medium", "low", "info"),
					"kill_chain":    str("revised attack-chain narrative"),
					"plain_english": str("revised plain-English explanation"),
					"remediation":   str("revised remediation"),
					"verification":  enumStr("evidence strength after verifying", "pattern_match", "verified"),
					"verified_by":   strArr("independent method(s) that confirmed it, e.g. send_request, dispatch_l2_probe:sqlmap"),
				}, "id"),
			},
			Handler: func(_ context.Context, args map[string]any, st *State) (ToolResult, error) {
				id := argStr(args, "id")
				f := findReport(st, id)
				if f == nil {
					return ToolResult{Err: true, Content: fmt.Sprintf("no L2 report with id %q — create_vulnerability_report first, or list the ids you've emitted", id)}, nil
				}
				if f.L2 == nil {
					f.L2 = &types.L2Report{}
				}
				var changed []string
				if s := argStr(args, "severity"); s != "" {
					sev := types.Severity(strings.ToLower(s))
					if !sev.Valid() {
						return ToolResult{Err: true, Content: "severity must be one of: critical, high, medium, low, info"}, nil
					}
					f.Severity = sev
					changed = append(changed, "severity")
				}
				if s := argStr(args, "kill_chain"); s != "" {
					f.L2.KillChain = s
					changed = append(changed, "kill_chain")
				}
				if s := argStr(args, "plain_english"); s != "" {
					f.L2.PlainEnglish, f.Description = s, s
					changed = append(changed, "plain_english")
				}
				if s := argStr(args, "remediation"); s != "" {
					f.L2.Remediation = s
					changed = append(changed, "remediation")
				}
				if vb := argStrList(args, "verified_by"); len(vb) > 0 {
					f.L2.VerifiedBy = mergeUnique(f.L2.VerifiedBy, vb)
					changed = append(changed, "verified_by")
				}
				if s := argStr(args, "verification"); s != "" {
					vs := types.VerificationState(s)
					if vs != types.VerificationPatternMatch && vs != types.VerificationVerified {
						return ToolResult{Err: true, Content: `verification must be "pattern_match" or "verified"`}, nil
					}
					// L2-4 discipline: a report may only become "verified" once
					// independent methods confirm it, and HIGH/CRITICAL need ≥2.
					if vs == types.VerificationVerified {
						if msg, ok := verifyGate(f.Severity, f.L2.VerifiedBy); !ok {
							return ToolResult{Err: true, Content: msg}, nil
						}
					}
					f.L2.Verification = vs
					changed = append(changed, "verification")
				}
				if len(changed) == 0 {
					return ToolResult{Content: fmt.Sprintf("%s unchanged (no fields supplied)", id)}, nil
				}
				return ToolResult{Content: fmt.Sprintf("updated %s: %s", id, strings.Join(changed, ", "))}, nil
			},
		},
		{
			Schema: ToolSchema{
				Name: "record_hypothesis",
				Description: "Persist a hypothesis / plan item to durable memory so it SURVIVES context compaction on a long scan. " +
					"Use it for the thread you intend to pursue (e.g. 'f-001 + f-004 may chain to account takeover; probe f-001 next'). " +
					"This is durable state, not a scratchpad — your between-call reasoning belongs in your response, not here.",
				Params: obj(map[string]any{
					"statement": str("what you believe / want to test"),
					"next_step": str("the concrete action it implies"),
				}, "statement"),
			},
			Handler: func(_ context.Context, args map[string]any, st *State) (ToolResult, error) {
				stmt := argStr(args, "statement")
				if strings.TrimSpace(stmt) == "" {
					return ToolResult{Err: true, Content: "statement is required"}, nil
				}
				st.Hypotheses = append(st.Hypotheses, Hypothesis{
					Statement: stmt,
					NextStep:  argStr(args, "next_step"),
				})
				return ToolResult{Content: fmt.Sprintf("recorded hypothesis #%d (survives compaction)", len(st.Hypotheses))}, nil
			},
		},
	}
}

// verifyGate enforces the L2-4 verification discipline: a report may only be
// marked "verified" once independent methods confirm it, and HIGH/CRITICAL
// require ≥2 INDEPENDENT methods (the ≥2-source rule) — a lone signature
// match is exactly the false-positive class L2 exists to filter, so claiming
// a critical is "verified" off one tool is forbidden. VerifiedBy is kept
// deduped (mergeUnique), so distinct entries ⇒ distinct methods.
func verifyGate(sev types.Severity, methods []string) (msg string, ok bool) {
	need := 1
	if sev == types.SeverityHigh || sev == types.SeverityCritical {
		need = 2
	}
	if len(methods) < need {
		return fmt.Sprintf(
			"OBSERVE: you marked a %s report verified with %d independent method(s). ORIENT: %s findings need ≥%d "+
				"(a lone signature match is the false-positive class L2 filters). DECIDE: gather another, independent "+
				"confirmation. ACT: send_request to confirm the response AND/OR dispatch_l2_probe(<tool>), then "+
				"update_finding(id, verified_by=[...]).",
			sev, len(methods), sev, need), false
	}
	return "", true
}

// findReport returns a pointer into st.Findings for the L2 report with the
// given id (so the handler mutates in place), or nil.
func findReport(st *State, id string) *types.Finding {
	for i := range st.Findings {
		if st.Findings[i].ID == id {
			return &st.Findings[i]
		}
	}
	return nil
}

// mergeUnique appends only the elements of add not already in base.
func mergeUnique(base, add []string) []string {
	seen := make(map[string]bool, len(base))
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range add {
		if s != "" && !seen[s] {
			base = append(base, s)
			seen[s] = true
		}
	}
	return base
}
