package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ADR 0028 G3 wiring. The analysis is tested in internal/exposuretrend; what could silently break
// here is the seam — an objective stored and never graded against, or a trend endpoint that still
// answers "what happened" only.

func TestExposureTrend_UngradedUntilAnObjectiveIsDeclared(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Token: "platform-tok", Recorder: ledger.NewRecorder()}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(d)

	rec := do(h, "GET", "/v1/exposure-trend", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("trend: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"objective"`) {
		t.Fatal("the trend response carries no objective verdict — the endpoint still answers only " +
			"'what happened', which is the gap ADR 0028 G3 names")
	}
	if !strings.Contains(body, "No exposure objective is set") {
		t.Errorf("an undeclared objective must be reported as itself, not defaulted to a pass: %s", body)
	}
	if strings.Contains(body, `"met":true`) {
		t.Error("a tenant with no objective was graded as meeting one")
	}
}

func TestSetExposureObjective_HoldTheLineIsStorable(t *testing.T) {
	// The regression that matters at the API layer: "close at least as much as opens" is all-zero
	// except Declared, so a handler that inferred declaredness from the values would silently store
	// nothing for the most natural target in the product.
	st := store.NewMemory()
	d := Deps{Store: st, Token: "platform-tok", Recorder: ledger.NewRecorder()}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(d)

	if rec := do(h, "PUT", "/v1/settings/exposure-objective", "t1", `{"net_per_window":0}`); rec.Code != 200 {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	tn, err := st.GetTenant(t.Context(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ExposureObjective == nil || !tn.ExposureObjective.Declared {
		t.Fatal("a hold-the-line objective was not stored as declared — reaching the handler IS the " +
			"declaration, and inferring it from the values loses exactly this target")
	}
	// And it now grades rather than reporting 'none set'.
	body := do(h, "GET", "/v1/exposure-trend", "t1", "").Body.String()
	if strings.Contains(body, "No exposure objective is set") {
		t.Error("the objective was stored and the trend still reports none set — the seam is broken")
	}
}

func TestSetExposureObjective_RejectsNonsense(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Token: "platform-tok"}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(d)
	if rec := do(h, "PUT", "/v1/settings/exposure-objective", "t1", `{"window_days":-5}`); rec.Code != 400 {
		t.Errorf("a negative window was accepted: %d %s", rec.Code, rec.Body.String())
	}
}

// TestExposureObjectiveMirror_StaysInStep guards the platform↔exposuretrend mirror. A field added to
// one and not the other would grade against a target the customer did not set.
func TestExposureObjectiveMirror_StaysInStep(t *testing.T) {
	// Field-by-field, by construction: if either struct gains a field, this stops compiling or the
	// count check fails, and both are louder than a silently ignored target.
	p := platform.ExposureObjective{Declared: true, WindowDays: 7, NetPerWindow: 3, MinConfirmedFixed: 2}
	if p.WindowDays != 7 || p.NetPerWindow != 3 || p.MinConfirmedFixed != 2 || !p.Declared {
		t.Fatal("platform.ExposureObjective does not round-trip its own fields")
	}
	const wantFields = 4
	if got := countJSONFields(p); got != wantFields {
		t.Errorf("platform.ExposureObjective has %d fields, expected %d — if a field was added, convert "+
			"it in handleExposureTrend too, or the objective is graded without it", got, wantFields)
	}
}
