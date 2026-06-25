package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func practDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	return Deps{Store: st, NewID: func() string { n++; return fmt.Sprintf("p%d", n) }}
}

func TestPractitioners_ServiceModelAndRoster(t *testing.T) {
	d := practDeps(t)

	// default service model is self_serve
	g0 := call(d, d.handleGetPractitioners, http.MethodGet, "/v1/practitioners", "", "")
	var out0 struct {
		ServiceModel  string                  `json:"service_model"`
		Practitioners []platform.Practitioner `json:"practitioners"`
	}
	_ = json.Unmarshal(g0.Body.Bytes(), &out0)
	if out0.ServiceModel != platform.ServiceSelfServe || len(out0.Practitioners) != 0 {
		t.Fatalf("default should be self_serve + empty roster, got %+v", out0)
	}

	// set the managed model (we provide the expert)
	if r := call(d, d.handleSetServiceModel, http.MethodPut, "/x", `{"service_model":"managed"}`, ""); r.Code != http.StatusOK {
		t.Fatalf("set service model: %d %s", r.Code, r.Body.String())
	}
	// invalid model rejected
	if r := call(d, d.handleSetServiceModel, http.MethodPut, "/x", `{"service_model":"nonsense"}`, ""); r.Code != http.StatusBadRequest {
		t.Errorf("invalid service model must be 400, got %d", r.Code)
	}

	// add a practitioner — capacity required + validated
	if r := call(d, d.handleAddPractitioner, http.MethodPost, "/x", `{"name":"Jordan"}`, ""); r.Code != http.StatusBadRequest {
		t.Errorf("missing capacity must be 400, got %d", r.Code)
	}
	if r := call(d, d.handleAddPractitioner, http.MethodPost, "/x", `{"name":"Jordan","capacity":"boss"}`, ""); r.Code != http.StatusBadRequest {
		t.Errorf("invalid capacity must be 400, got %d", r.Code)
	}
	arec := call(d, d.handleAddPractitioner, http.MethodPost, "/x",
		`{"name":"Jordan Lee","firm":"TensorShield Managed","credential":"vCISO, CISSP","capacity":"managed","scope":["vciso","risk"]}`, "")
	if arec.Code != http.StatusOK {
		t.Fatalf("add practitioner: %d %s", arec.Code, arec.Body.String())
	}
	var p platform.Practitioner
	_ = json.Unmarshal(arec.Body.Bytes(), &p)
	if p.Capacity != platform.CapacityManaged || p.Firm != "TensorShield Managed" {
		t.Fatalf("practitioner not stored correctly: %+v", p)
	}

	// list reflects the managed model + the one practitioner
	g1 := call(d, d.handleGetPractitioners, http.MethodGet, "/v1/practitioners", "", "")
	var out1 struct {
		ServiceModel  string                  `json:"service_model"`
		Practitioners []platform.Practitioner `json:"practitioners"`
	}
	_ = json.Unmarshal(g1.Body.Bytes(), &out1)
	if out1.ServiceModel != "managed" || len(out1.Practitioners) != 1 {
		t.Fatalf("expected managed + 1 practitioner, got %+v", out1)
	}

	// delete
	dreq := call(d, d.handleDeletePractitioner, http.MethodDelete, "/x", "", p.ID)
	if dreq.Code != http.StatusOK {
		t.Fatalf("delete: %d", dreq.Code)
	}
	if r := call(d, d.handleDeletePractitioner, http.MethodDelete, "/x", "", "nope"); r.Code != http.StatusNotFound {
		t.Errorf("delete unknown must be 404, got %d", r.Code)
	}
}
