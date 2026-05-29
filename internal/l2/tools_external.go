package l2

import "context"

// External-service interfaces — the seam to real-time data + re-dispatch +
// live verification. Production wires adapters (threat-intel corpus,
// compliance corpus, the /replay handler, an HTTP client); tests wire
// mocks. All return rendered TEXT (the tool result the LLM reads), keeping
// the agent decoupled from the concrete data shapes.

// ThreatIntelLookup answers CVE → CVSS/KEV/EPSS/advisory summary (§2.7:
// real-time data past the model's training cutoff).
type ThreatIntelLookup interface {
	LookupCVE(ctx context.Context, cve string) (summary string, found bool)
}

// ComplianceLookup answers CWE-set → affected control summary (SOC2/PCI/…).
type ComplianceLookup interface {
	MapCWE(cwes []string) (summary string)
}

// Prober re-fires a deterministic L1/registry tool via /replay — the
// LLM-can't-run-subprocess §2.7 tool. This is L2's depth lever (vs. raw
// shell). Returns a rendered summary of the probe's findings.
type Prober interface {
	Probe(ctx context.Context, tool string, args map[string]any) (summary string, err error)
}

// HTTPDoer issues one HTTP request (verification only — confirm a
// pattern_match without re-crafting an exploit). Returns a rendered
// status+headers+truncated-body summary.
type HTTPDoer interface {
	Do(ctx context.Context, method, url string, headers map[string]string, body string) (summary string, err error)
}

// externalTools builds the fetch-external / re-dispatch / primitive tools.
// L2-1 stub (returns nil); L2-3 fills it in. Tools whose backing service is
// nil are skipped, so a partial Deps still yields a valid catalog.
func externalTools(_ Deps) Catalog { return nil }
