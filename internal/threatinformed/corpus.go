package threatinformed

import (
	"encoding/json"
	"fmt"
	"os"
)

// CorpusEnv names the env var pointing at the refreshed on-disk threat-intel
// corpus. It is deliberately the SAME variable the L1.5 threat_intel hook
// reads, so annotation and targeting always agree about which world-state they
// are working from (and the scan's pinned corpus version covers both).
const CorpusEnv = "TSENGINE_THREAT_INTEL_CORPUS"

// LoadCorpus reads a threat-intel corpus file — a bare map[CVE]Entry, the same
// byte shape the L1.5 hook consumes — and returns the targeting-relevant view.
func LoadCorpus(path string) (Corpus, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured corpus path, not a scan target
	if err != nil {
		return nil, fmt.Errorf("threatinformed: read corpus: %w", err)
	}
	var c Corpus
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("threatinformed: parse corpus: %w", err)
	}
	return c, nil
}

// CorpusFromEnv loads the corpus named by CorpusEnv. It returns (nil, false)
// when the variable is unset OR the file is unreadable/malformed: targeting is
// an ENHANCEMENT, so a missing or broken corpus must degrade to "no targeted
// probes" and never fail a scan (§10 — no corpus, no claims).
func CorpusFromEnv() (Corpus, bool) {
	p := os.Getenv(CorpusEnv)
	if p == "" {
		return nil, false
	}
	c, err := LoadCorpus(p)
	if err != nil || len(c) == 0 {
		return nil, false
	}
	return c, true
}
