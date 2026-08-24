package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The wiring test, because the stamp existing is not the same as the report carrying it — the
// defect this session keeps finding is a capability reachable only from its own test.
func TestVAPTReport_CarriesDetectionProvenanceFromDeps(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, GRC: &grc.GRC{Store: st}, Token: "platform-tok", ScanImage: "tsengine/sandbox:latest"}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1", Name: "AcmeCo"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(d)

	rec := do(h, "GET", "/v1/vapt/report", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Detection corpus:") {
		t.Error("the rendered report carries no detection provenance. Deps.ScanImage is set, the stamp " +
			"exists and grc renders it — so this is the seam, which is exactly where the last four of " +
			"these defects lived.")
	}
	if !strings.Contains(body, "mutable tag") {
		t.Error("the image is a tag and the report does not say a tag cannot identify the build. " +
			"Printing the reference without that sentence makes it look like an identity.")
	}
}

func TestVAPTReport_NoScanImageStaysSilent(t *testing.T) {
	// A deployment that has not wired it (or NO_ENGINE) must not gain an empty or invented line.
	st := store.NewMemory()
	d := Deps{Store: st, GRC: &grc.GRC{Store: st}, Token: "platform-tok"}
	if err := st.PutTenant(t.Context(), platform.Tenant{ID: "t1", Name: "AcmeCo"}); err != nil {
		t.Fatal(err)
	}
	rec := do(NewHandler(d), "GET", "/v1/vapt/report", "t1", "")
	// Guard against a vacuous pass: an error page also contains no provenance line. The first
	// version of this test asserted absence against a 401 and "passed".
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Penetration Test") {
		t.Fatalf("the report did not render, so asserting absence proves nothing: %d %s",
			rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Detection corpus:") {
		t.Error("a deployment with no configured scan image rendered a detection-corpus line anyway")
	}
}
