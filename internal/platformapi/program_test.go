package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func programDeps(t *testing.T) (Deps, *ledger.Recorder) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	rec := ledger.NewRecorder()
	return Deps{Store: st, Recorder: rec}, rec
}

func TestProgram_SeedPublishAck(t *testing.T) {
	d, rec := programDeps(t)

	// 1) seed the standard policy set (drafts)
	srec := call(d, d.handleSeedProgram, http.MethodPost, "/v1/program/seed", "", "")
	if srec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", srec.Code, srec.Body.String())
	}
	var seedOut struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(srec.Body.Bytes(), &seedOut)
	if seedOut.Count == 0 {
		t.Fatal("seed should create the standard policy set")
	}
	// re-seed is idempotent
	srec2 := call(d, d.handleSeedProgram, http.MethodPost, "/v1/program/seed", "", "")
	var seed2 struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(srec2.Body.Bytes(), &seed2)
	if seed2.Count != 0 {
		t.Errorf("re-seed should add nothing, got %d", seed2.Count)
	}

	pid := "policy-information-security-policy"

	// 2) ack before publish → 400 (only a published policy is acknowledgeable)
	if r := call(d, d.handleAckPolicy, http.MethodPost, "/x", `{"user":"sam@acme.com"}`, pid); r.Code != http.StatusBadRequest {
		t.Errorf("ack of a draft must be 400, got %d", r.Code)
	}

	// 3) publish requires a named owner
	if r := call(d, d.handlePublishPolicy, http.MethodPost, "/x", `{}`, pid); r.Code != http.StatusBadRequest {
		t.Errorf("publish without owner must be 400, got %d", r.Code)
	}
	prec := call(d, d.handlePublishPolicy, http.MethodPost, "/x", `{"owner":"Jordan (CISO)"}`, pid)
	if prec.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", prec.Code, prec.Body.String())
	}
	var pub platform.Policy
	_ = json.Unmarshal(prec.Body.Bytes(), &pub)
	if pub.Status != platform.PolicyPublished || pub.Owner != "Jordan (CISO)" || pub.LedgerRef == "" {
		t.Fatalf("expected a published policy owned + ledgered, got %+v", pub)
	}

	// 4) acknowledge (idempotent per user)
	call(d, d.handleAckPolicy, http.MethodPost, "/x", `{"user":"sam@acme.com"}`, pid)
	call(d, d.handleAckPolicy, http.MethodPost, "/x", `{"user":"sam@acme.com"}`, pid) // dup
	arec := call(d, d.handleAckPolicy, http.MethodPost, "/x", `{"user":"lee@acme.com"}`, pid)
	var acked platform.Policy
	_ = json.Unmarshal(arec.Body.Bytes(), &acked)
	if len(acked.Acks) != 2 { // sam (deduped) + lee
		t.Errorf("expected 2 distinct acks, got %d: %+v", len(acked.Acks), acked.Acks)
	}
	if len(rec.Steps()) == 0 {
		t.Error("the publish must be recorded into the ledger")
	}
}
