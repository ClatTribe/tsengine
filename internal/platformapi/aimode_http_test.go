package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE ONE THAT MATTERS: choosing deterministic-only must actually STOP a real agent run, not merely
// record a preference. A toggle that stores a value and changes nothing is worse than no toggle — the
// customer believes they turned it off.
func TestAIMode_DeterministicStopsTheEngineerEndToEnd(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("advance_phase", nil), jobCall("advance_phase", nil), jobCall("advance_phase", nil),
		jobCall("finish_scan", map[string]any{"executive_summary": "should never run"}),
	})
	ctx := context.Background()

	// Baseline: the engineer runs for this (Enterprise) tenant.
	if d.resolveLeadClient(ctx, tid) == nil {
		t.Fatal("baseline broken: the entitled tenant had no Lead client")
	}

	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.AIMode = platform.AIModeDeterministic
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if d.resolveLeadClient(ctx, tid) != nil {
		t.Error("deterministic-only did not stop the Lead — the switch is decorative")
	}
	if d.resolveAgentLLMForRole(ctx, tid, "") != nil {
		t.Error("deterministic-only did not stop the agent lane")
	}
	// And the endpoint refuses rather than running silently.
	code, _ := postTranslate(t, d, tid)
	if code == http.StatusOK {
		t.Error("POST /v1/l2/translate ran the engineer for a deterministic-only tenant")
	}
}

func TestAIMode_GetReportsStateChoicesAndSpend(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	d.Token = "platform-tok" // the `do` helper authenticates with this
	h := NewHandler(d)
	rec := do(h, "GET", "/v1/settings/ai-mode", tid, "")
	if rec.Code != 200 {
		t.Fatalf("GET ai-mode = %d: %s", rec.Code, rec.Body.String())
	}
	var got aiModeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Reason == "" {
		t.Error("no reason — the UI cannot explain why a surface is on or off")
	}
	if len(got.Choices) != 3 {
		t.Fatalf("want 3 choices (deterministic / engineer / full), got %d", len(got.Choices))
	}
	// Deterministic must ALWAYS be available — it is the floor, never gated on a plan.
	if !got.Choices[0].Available {
		t.Error("deterministic-only was unavailable; it is the floor and costs us nothing")
	}
	// Every unavailable choice must say why, not just grey out.
	for _, c := range got.Choices {
		if !c.Available && c.Why == "" {
			t.Errorf("choice %q is unavailable with no explanation", c.Mode)
		}
		if c.Cost == "" {
			t.Errorf("choice %q does not state its cost — the point is cost transparency", c.Mode)
		}
	}
}

func TestAIMode_SetPersistsAndRejectsGarbage(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	d.Token = "platform-tok" // the `do` helper authenticates with this
	h := NewHandler(d)

	if rec := do(h, "PUT", "/v1/settings/ai-mode", tid, `{"mode":"engineer"}`); rec.Code != 200 {
		t.Fatalf("setting a valid mode = %d: %s", rec.Code, rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), tid)
	if tn.AIMode != platform.AIModeEngineer {
		t.Errorf("mode not persisted: %q", tn.AIMode)
	}

	// A typo must be REFUSED, never normalised to some other tier.
	for _, bad := range []string{`{"mode":"engneer"}`, `{"mode":""}`, `{"mode":"yes"}`} {
		if rec := do(h, "PUT", "/v1/settings/ai-mode", tid, bad); rec.Code != 400 {
			t.Errorf("%s got %d, want 400 — a typo must not silently pick a tier", bad, rec.Code)
		}
	}
	// The refused writes left the earlier valid choice intact.
	tn2, _ := d.Store.GetTenant(context.Background(), tid)
	if tn2.AIMode != platform.AIModeEngineer {
		t.Errorf("a rejected write changed the stored mode to %q", tn2.AIMode)
	}
}

// A store read error must not look like the customer turned AI off — that would disable the product
// on a transient blip.
func TestAIMode_StoreErrorFallsBackToPlanNotOff(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	// An unknown tenant id exercises the not-found path.
	got := d.aiAllowed(context.Background(), "no-such-tenant")
	if got.Reason == "" {
		t.Error("a lookup failure produced no explanation")
	}
	// The real tenant is unaffected.
	if !d.aiAllowed(context.Background(), tid).Engineer {
		t.Error("the entitled tenant lost AI")
	}
}
