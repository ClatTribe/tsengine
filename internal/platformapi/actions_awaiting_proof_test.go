package platformapi

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func act(id, class, status string, v *platform.FixVerification) platform.Action {
	return platform.Action{ID: id, TenantID: "t1", Status: platform.ActApplied,
		FindingKeys: []string{class + "|https://x/" + id}, Verification: v}
}

// The roll-up switched on STRING LITERALS, so adding a third verification status skipped it silently:
// a withheld confirmation counted as Verified and landed in NO bucket, and the roll-up's own numbers
// stopped adding up. The missing one is the fix a customer most needs to hear about.
func TestActionsRollup_AwaitingProofIsCountedAsItself(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAction(ctx, act("a1", "nuclei::sqli", "", &platform.FixVerification{Status: platform.FixStatusFixed}))
	_ = st.PutAction(ctx, act("a2", "nuclei::sqli", "", &platform.FixVerification{Status: platform.FixStatusStillPresent}))
	_ = st.PutAction(ctx, act("a3", "nuclei::sqli", "", &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed}))

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/actions", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("GET /v1/actions: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)

	num := func(k string) int { f, _ := got[k].(float64); return int(f) }
	if num("verified") != 3 {
		t.Fatalf("verified = %d, want 3", num("verified"))
	}
	if num("confirmed_fix") != 1 || num("still_present") != 1 || num("awaiting_proof") != 1 {
		t.Errorf("want 1/1/1, got confirmed=%d still=%d awaiting=%d",
			num("confirmed_fix"), num("still_present"), num("awaiting_proof"))
	}
	// The property behind the counts: every verified action lands in exactly one bucket.
	if sum := num("confirmed_fix") + num("still_present") + num("awaiting_proof"); sum != num("verified") {
		t.Errorf("the buckets must account for every verified action: %d != %d", sum, num("verified"))
	}
}

// The product stating where its OWN absence-evidence has failed. Distrusted() was written last
// iteration and had no caller outside its own tests — the silent-signal bug this campaign keeps
// finding, freshly authored.
func TestActionsRollup_NamesTheClassesWhoseRescansHaveBeenContradicted(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	for i := 0; i < 6; i++ {
		_ = st.PutAction(ctx, act("h"+strconv.Itoa(i), "nuclei::sqli", "", &platform.FixVerification{
			Status: platform.FixStatusFixed, RescanSaidFixed: true,
			Disagreement: platform.DisagreeRescanMissedLiveExploit}))
	}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/actions", "t1", "")
	var got struct {
		Distrusted []struct {
			Class        string `json:"class"`
			Contradicted int    `json:"contradicted"`
			CleanRescans int    `json:"clean_rescans"`
		} `json:"distrusted_classes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Distrusted) != 1 {
		t.Fatalf("want the contradicted class named, got %+v", got.Distrusted)
	}
	if got.Distrusted[0].Class != "nuclei::sqli" || got.Distrusted[0].Contradicted != 6 {
		t.Errorf("the record must carry the real counts, got %+v", got.Distrusted[0])
	}
}

// "We have not caught ourselves being wrong here" is not "we are never wrong here". A tenant with no
// contradicted history must name nothing at all rather than an empty-but-present reassurance.
func TestActionsRollup_NoContradictionsNamesNothing(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	for i := 0; i < 6; i++ {
		_ = st.PutAction(ctx, act("h"+strconv.Itoa(i), "nuclei::sqli", "", &platform.FixVerification{
			Status: platform.FixStatusFixed, RescanSaidFixed: true}))
	}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/actions", "t1", "")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if _, present := got["distrusted_classes"]; present {
		t.Errorf("a clean record must name nothing, got %v", got["distrusted_classes"])
	}
	if f, _ := got["awaiting_proof"].(float64); int(f) != 0 {
		t.Errorf("nothing should await proof here, got %v", got["awaiting_proof"])
	}
}
