package webagent

import (
	"context"
	"testing"
)

// TestWorldStore_RoundTrip (P5): a persisted model loads back equal (redacted — no raw token stored).
func TestWorldStore_RoundTrip(t *testing.T) {
	turns := []Turn{
		{ID: "t-1", Method: "GET", URL: "https://app.acme.com/search?q=x", Status: 200},
		{ID: "t-2", Method: "POST", URL: "https://app.acme.com/login", Status: 200, SetCookies: []string{"session=SECRETTOK; Path=/"}},
		{ID: "t-3", Method: "ssh_exec", URL: "u@10.0.0.5:22", Status: 200},
	}
	w := BuildWorldModel(turns, nil)
	st := NewMemoryWorldStore()
	if err := st.Save(context.Background(), "eng-1", w); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.Load(context.Background(), "eng-1")
	if err != nil || !ok {
		t.Fatalf("load failed: ok=%v err=%v", ok, err)
	}
	if len(got.Endpoints) != len(w.Endpoints) || len(got.Edges) != 1 || len(got.Identities) != 1 {
		t.Errorf("round-trip lost data: %+v", got)
	}
	if got.FirstWebHost != "app.acme.com" {
		t.Errorf("pivot source must round-trip, got %q", got.FirstWebHost)
	}
	// the persisted identity is a fingerprint, never the raw token
	if got.Identities[0].Fingerprint == "SECRETTOK" || got.Identities[0].Fingerprint == "" {
		t.Errorf("persisted identity must be a redacted fingerprint, got %q", got.Identities[0].Fingerprint)
	}
	if _, ok, _ := st.Load(context.Background(), "absent"); ok {
		t.Error("an absent key must load ok=false")
	}
}

// TestWorldModel_Merge (P5): a resumed engagement folds in the prior model — surface + a confirmed class
// carry forward, deduped.
func TestWorldModel_Merge(t *testing.T) {
	prior := BuildWorldModel(
		[]Turn{{ID: "t-1", Method: "GET", URL: "https://app.acme.com/admin", Status: 200}},
		[]Finding{{ID: "f-1", Route: "https://app.acme.com/admin", Class: "idor", Evidence: []string{"t-1"}}},
	)
	// a fresh engagement that only saw /search
	now := BuildWorldModel([]Turn{{ID: "n-1", Method: "GET", URL: "https://app.acme.com/search?q=1", Status: 200}}, nil)
	now.Merge(prior)

	if _, ok := now.Endpoints["GET https://app.acme.com/admin"]; !ok {
		t.Error("merge must carry forward the prior /admin endpoint")
	}
	if _, ok := now.Endpoints["GET https://app.acme.com/search"]; !ok {
		t.Error("the current /search endpoint must remain")
	}
	if e := now.Endpoints["GET https://app.acme.com/admin"]; e == nil || e.Tested["idor"] != "confirmed" {
		t.Error("the prior confirmed idor must carry forward")
	}
	// merging again is idempotent (no duplicate attempts/edges)
	before := len(now.Attempts)
	now.Merge(prior)
	if len(now.Attempts) != before {
		t.Errorf("re-merge must be idempotent: %d -> %d", before, len(now.Attempts))
	}
}
