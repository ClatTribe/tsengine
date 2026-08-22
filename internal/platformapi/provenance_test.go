package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Every producer that shares the persist path must record its OWN provenance.
//
// The path was copied and its labels were not: reusing the drift persister stamped ids "drift-…",
// marked the clouddrift posture assessed, and wrote "cloud drift detected" — first for a SAML trust
// weakness, then for a source-code finding. Neither is drift. Drift asserts that something CHANGED,
// and in both cases nothing had; the ledger is where a claim is meant to be checkable.
//
// This is a table so the next producer added here has to declare what it is, and a copied label
// fails rather than shipping as a quiet claim about an event that did not happen.
func TestFindingProvenance_EachProducerRecordsItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name string
		prov findingProvenance
	}{
		{"drift", driftProvenance},
		{"ci-identity", ciIdentityProvenance},
		{"code-sweep", codeSweepProvenance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prov.IDPrefix == "" || tc.prov.PostureKind == "" || tc.prov.LedgerWhat == "" {
				t.Fatalf("incomplete provenance: %+v", tc.prov)
			}
			// Only the genuine drift producer may say drift. For anyone else the word asserts an
			// event that did not occur.
			if tc.name == "drift" {
				return
			}
			blob := strings.ToLower(tc.prov.IDPrefix + " " + tc.prov.PostureKind + " " +
				tc.prov.LedgerWhat + " " + tc.prov.LedgerTool + " " + tc.prov.LedgerWhy)
			if strings.Contains(blob, "drift") {
				t.Errorf("%s claims drift, which asserts that something changed: %+v", tc.name, tc.prov)
			}
		})
	}
}

// And the labels are distinct, so "did the code sweep run?" is answerable separately from "did drift
// detection run?" — the whole point of a per-producer posture kind.
func TestFindingProvenance_KindsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for name, p := range map[string]findingProvenance{
		"drift": driftProvenance, "ci-identity": ciIdentityProvenance, "code-sweep": codeSweepProvenance,
	} {
		if prev, dup := seen[p.PostureKind]; dup {
			t.Errorf("%s and %s share posture kind %q — one running would imply the other did",
				name, prev, p.PostureKind)
		}
		seen[p.PostureKind] = name
	}
}

// End to end: a code-sweep finding is not recorded as drift.
func TestPersistFindings_CodeSweepIsNotDrift(t *testing.T) {
	rec := ledger.NewRecorder()
	d := Deps{Store: store.NewMemory(), Recorder: rec, NewID: func() string { return "1" }}

	saved, n := d.persistFindings(context.Background(), "t1", []types.Finding{{
		RuleID: "codesweep::cwe-89", Tool: "codesweep", Severity: types.SeverityHigh,
		Endpoint: "internal/api/handler.go", Title: "SQL built by concatenation",
	}}, codeSweepProvenance)
	if n != 1 || len(saved) != 1 {
		t.Fatalf("not stored: n=%d", n)
	}
	if strings.HasPrefix(saved[0].ID, "drift") {
		t.Errorf("a source-code finding carries a drift id: %q", saved[0].ID)
	}
	for _, st := range rec.Steps() {
		if strings.Contains(strings.ToLower(st.Thought+st.Tool), "drift") {
			t.Errorf("a source-code finding was recorded as drift: %q / %q", st.Thought, st.Tool)
		}
	}
}
