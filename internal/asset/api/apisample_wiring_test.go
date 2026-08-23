package api

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	_ "github.com/ClatTribe/tsengine/internal/tool/apisample" // register the tool under test
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// These test the DISPATCH, not the tool. A tool can be perfect and never run: ADR
// 0026 records apiauthz as exactly that — a real differential BOLA/BFLA prober that
// no normal scan reaches — and the repo has found the same shape in ghoidc and
// codesweep. Calling apiexposure.Assess directly would pass with this wiring deleted.

func dispatchFor(t *testing.T, toolName string, ds []asset.Dispatch) (asset.Dispatch, bool) {
	t.Helper()
	for _, d := range ds {
		if d.Tool != nil && d.Tool.Name() == toolName {
			return d, true
		}
	}
	return asset.Dispatch{}, false
}

func TestFanoutDispatchesTheResponseSampler(t *testing.T) {
	h := NewHandler()
	surface := []string{
		openapiSpecMarker + " http://api.test/openapi.json",
		"GET http://api.test/users/v1",
		"GET http://api.test/books/v1",
	}
	ds := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: "http://api.test"}, surface)

	d, ok := dispatchFor(t, "api_response_sample", ds)
	if !ok {
		var names []string
		for _, x := range ds {
			if x.Tool != nil {
				names = append(names, x.Tool.Name())
			}
		}
		t.Fatalf("api_response_sample was NOT dispatched; fan-out planned %v.\n"+
			"OWASP API3 coverage depends on this dispatch — without it the detector is unreachable.", names)
	}

	targets, _ := d.Args["targets"].(string)
	for _, want := range []string{"/users/v1", "/books/v1"} {
		if !strings.Contains(targets, want) {
			t.Errorf("declared operation %q missing from sampler targets:\n%s", want, targets)
		}
	}
}

// With no surface there is nothing to sample, and dispatching anyway would send
// requests nobody asked for.
func TestNoSurfaceMeansNoSampler(t *testing.T) {
	h := NewHandler()
	ds := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: ""}, nil)
	if _, ok := dispatchFor(t, "api_response_sample", ds); ok {
		t.Fatal("sampler dispatched with an empty surface — it would probe nothing, or worse, guess")
	}
}

// The sampler must receive the same endpoint set nuclei does. If they drift, the
// asset scans one surface for signatures and a different one for exposure, and the
// difference is invisible in any report.
func TestSamplerAndNucleiAgreeOnTheSurface(t *testing.T) {
	h := NewHandler()
	surface := []string{
		openapiSpecMarker + " http://api.test/openapi.json",
		"GET http://api.test/a",
		"POST http://api.test/b",
	}
	ds := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: "http://api.test"}, surface)

	smp, ok := dispatchFor(t, "api_response_sample", ds)
	if !ok {
		t.Fatal("sampler not dispatched")
	}
	nuc, ok := dispatchFor(t, "nuclei", ds)
	if !ok {
		t.Skip("nuclei not registered in this binary") //nolint:staticcheck // the assertion below needs both
	}
	if smp.Args["targets"] != nuc.Args["targets"] {
		t.Errorf("sampler and nuclei were given different surfaces:\n sampler: %v\n nuclei:  %v",
			smp.Args["targets"], nuc.Args["targets"])
	}
}
