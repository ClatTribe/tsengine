package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func vendorDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	return Deps{Store: st, NewID: func() string { n++; return "id" + string(rune('a'+n)) }}
}

func listVendors(t *testing.T, d Deps) vendorsResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleListVendors(rec, httptest.NewRequest(http.MethodGet, "/v1/vendors", nil), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/vendors: %d %s", rec.Code, rec.Body.String())
	}
	var out vendorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// THE REASON THE REGISTER EXISTS. The posted inventory used to be assessed and discarded: the
// findings persisted and the portfolio did not, so nobody could answer "who are our vendors".
func TestPostedInventoryLandsInTheRegisterNotJustInFindings(t *testing.T) {
	d := vendorDeps(t)
	body := `{"vendors":[{"name":"Acme Analytics","data_access":"pii","subprocessor":true},
	                     {"name":"Bolt Payments","handles_card_data":true}]}`
	rec := httptest.NewRecorder()
	d.handleTPRMIngest(rec, httptest.NewRequest(http.MethodPost, "/v1/tprm/ingest", strings.NewReader(body)), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	got := listVendors(t, d)
	if got.Summary.Total != 2 {
		t.Fatalf("register holds %d vendors after an ingest of 2: %+v", got.Summary.Total, got.Vendors)
	}
	if got.Summary.Subprocessors != 1 {
		t.Errorf("subprocessors = %d, want 1", got.Summary.Subprocessors)
	}
	for _, v := range got.Vendors {
		if v.Source != "ingest" {
			t.Errorf("%s came from the ingest and is recorded as %q — a posted inventory and a "+
				"hand-kept register are different claims about completeness", v.Name, v.Source)
		}
	}
}

// Re-posting the same inventory must UPDATE each vendor, not accumulate copies. A register that
// doubles every night is not one anybody can read.
func TestReIngestUpdatesRatherThanDuplicating(t *testing.T) {
	d := vendorDeps(t)
	post := func(body string) {
		rec := httptest.NewRecorder()
		d.handleTPRMIngest(rec, httptest.NewRequest(http.MethodPost, "/v1/tprm/ingest", strings.NewReader(body)), "ten-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
		}
	}
	post(`{"vendors":[{"name":"Acme Analytics","data_access":"pii"}]}`)
	post(`{"vendors":[{"name":"Acme Analytics","data_access":"sensitive","certifications":["SOC2"]}]}`)

	got := listVendors(t, d)
	if got.Summary.Total != 1 {
		t.Fatalf("re-ingest produced %d rows for one vendor", got.Summary.Total)
	}
	if got.Vendors[0].DataAccess != platform.VendorDataSensitive {
		t.Errorf("the second post did not update the row: %+v", got.Vendors[0])
	}
}

// BOTH DOORS, ONE REGISTER. A row a person adds and an inventory a job posts must produce the same
// register and the same findings — this codebase has found the two-doors-disagree bug three times.
func TestTheEditorAndTheIngestShareOneRegisterAndOneAssessment(t *testing.T) {
	d := vendorDeps(t)
	rec := httptest.NewRecorder()
	d.handlePutVendor(rec, httptest.NewRequest(http.MethodPost, "/v1/vendors",
		strings.NewReader(`{"name":"Cobalt CRM","data_access":"pii","owner":"ada@acme.io"}`)), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	// A PII vendor with no certification is a real finding — the editor door must produce it too,
	// not only the ingest.
	fs, _ := d.Store.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if len(fs) == 0 {
		t.Fatal("adding a PII vendor with no certification through the editor raised no finding — " +
			"the two doors assess differently")
	}
	if got := listVendors(t, d); got.Vendors[0].Source != "register" {
		t.Errorf("source = %q, want register", got.Vendors[0].Source)
	}
}

// A row nobody can name cannot be reviewed, cited, or matched against a later inventory.
func TestAVendorWithNoNameIsRefused(t *testing.T) {
	d := vendorDeps(t)
	rec := httptest.NewRecorder()
	d.handlePutVendor(rec, httptest.NewRequest(http.MethodPost, "/v1/vendors", strings.NewReader(`{"data_access":"pii"}`)), "ten-1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for an unnamed vendor, got %d", rec.Code)
	}
}

// Removing a vendor re-assesses, so a relationship that has ended stops raising risks about itself.
func TestDeletingAVendorClearsItsRisks(t *testing.T) {
	d := vendorDeps(t)
	rec := httptest.NewRecorder()
	d.handlePutVendor(rec, httptest.NewRequest(http.MethodPost, "/v1/vendors",
		strings.NewReader(`{"name":"Cobalt CRM","data_access":"pii"}`)), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodDelete, "/v1/vendors/cobalt-crm", nil)
	req.SetPathValue("id", "cobalt-crm")
	rec2 := httptest.NewRecorder()
	d.handleDeleteVendor(rec2, req, "ten-1")
	if rec2.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", rec2.Code, rec2.Body.String())
	}
	if got := listVendors(t, d); got.Summary.Total != 0 {
		t.Fatalf("register still holds %d after delete", got.Summary.Total)
	}
}

// AN EMPTY REGISTER IS NOT A CLEAN ONE. A company with nothing written down and a company with no
// vendor risk are indistinguishable in a findings list, so the summary says which this is.
func TestAnEmptyRegisterSaysSoRatherThanReadingClean(t *testing.T) {
	d := vendorDeps(t)
	got := listVendors(t, d)
	if got.Summary.Total != 0 {
		t.Fatalf("fresh tenant has %d vendors", got.Summary.Total)
	}
	if !strings.Contains(got.Summary.Detail, "empty register, not a clean one") {
		t.Errorf("detail does not refuse the comfortable reading: %q", got.Summary.Detail)
	}
}

// An UNOWNED vendor is one nobody has agreed to be accountable for, and a NEVER-reviewed one is
// different from one reviewed long ago. Both are counted, and neither is filled in for the customer.
func TestUnownedAndNeverReviewedAreCountedNotPapredOver(t *testing.T) {
	d := vendorDeps(t)
	rec := httptest.NewRecorder()
	d.handlePutVendor(rec, httptest.NewRequest(http.MethodPost, "/v1/vendors",
		strings.NewReader(`{"name":"Cobalt CRM","data_access":"pii"}`)), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d", rec.Code)
	}
	got := listVendors(t, d)
	if got.Summary.Unowned != 1 || got.Summary.NeverReviewed != 1 {
		t.Fatalf("unowned=%d never_reviewed=%d, want 1/1: %+v", got.Summary.Unowned, got.Summary.NeverReviewed, got.Summary)
	}
	if got.Vendors[0].Owner != "" {
		t.Error("an owner was invented — defaulting to the workspace owner names somebody who never " +
			"agreed to be accountable for the relationship")
	}
	if !strings.Contains(got.Summary.Detail, "no named owner") {
		t.Errorf("detail does not surface the unowned rows: %q", got.Summary.Detail)
	}
}
