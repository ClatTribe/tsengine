package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func dpHandler(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	return NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}), st
}

type dpResp struct {
	Objects        int              `json:"objects"`
	Grants         int              `json:"grants"`
	IssuesDetected int              `json:"issues_detected"`
	ChecksNotRun   []string         `json:"checks_not_run"`
	Discovered     []map[string]any `json:"discovered_sensitive"`
}

func postEstate(t *testing.T, h http.Handler, body string) dpResp {
	t.Helper()
	rec := do(h, "POST", "/v1/dataplatform/ingest", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out dpResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	return out
}

// The whole point, end to end: a grant snapshot becomes findings in the same store every other surface
// writes to, so warehouse access flows through issues / incidents / grc / hitl like anything else.
func TestDataPlatform_EndToEnd(t *testing.T) {
	h, st := dpHandler(t)
	got := postEstate(t, h, `{
	  "org_domains":["acme.io"],
	  "objects":[
	    {"platform":"snowflake","name":"analytics.public.customers","type":"table","sensitive":true,
	     "data_classes":["pii"],
	     "grants":[{"grantee":"allUsers","privilege":"SELECT"},
	               {"grantee":"analyst_role","privilege":"SELECT","last_used":"2026-08-13"}]},
	    {"platform":"bigquery","name":"proj.ds.lookup","type":"table",
	     "grants":[{"grantee":"analyst_role","privilege":"SELECT","last_used":"2026-08-13"}]}
	  ]}`)
	if got.Objects != 2 || got.Grants != 3 {
		t.Errorf("counts = %d objects / %d grants, want 2 / 3", got.Objects, got.Grants)
	}
	if got.IssuesDetected != 1 {
		t.Fatalf("want exactly the internet-readable table, got %d issues", got.IssuesDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("stored %d findings, want 1", len(fs))
	}
	if fs[0].Tool != "dataplatform" {
		t.Errorf("tool = %q, want dataplatform", fs[0].Tool)
	}
	if fs[0].Endpoint != "snowflake:analytics.public.customers" {
		t.Errorf("endpoint = %q — a responder must be able to find the object from it", fs[0].Endpoint)
	}
	if fs[0].ID == "" {
		t.Error("stored finding has no id")
	}
}

// A clean snapshot must store nothing. This is what makes a zero result trustworthy.
func TestDataPlatform_GovernedEstateStoresNothing(t *testing.T) {
	h, st := dpHandler(t)
	got := postEstate(t, h, `{
	  "org_domains":["acme.io"],
	  "objects":[{"platform":"snowflake","name":"analytics.public.customers","type":"table","sensitive":true,
	    "grants":[{"grantee":"analyst_role","privilege":"SELECT","last_used":"2026-08-13"}]}]}`)
	if got.IssuesDetected != 0 {
		t.Errorf("a governed warehouse reported %d issues", got.IssuesDetected)
	}
	if fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{}); len(fs) != 0 {
		t.Errorf("stored %d findings for a governed warehouse", len(fs))
	}
}

// THE HONESTY THAT HAS TO REACH THE WIRE.
//
// Three checks stay silent by design when the data to ground them is absent (§10). Silence is correct —
// but a caller who sees "0 issues" and is not told which checks never ran will read it as a clean
// warehouse. That misreading is the exact false assurance the refusals exist to prevent, so the refusal
// is only honest if the response says it happened.
func TestDataPlatform_SaysWhichChecksDidNotRun(t *testing.T) {
	h, _ := dpHandler(t)
	got := postEstate(t, h, `{"objects":[
	  {"platform":"snowflake","name":"db.public.t","type":"table",
	   "grants":[{"grantee":"contractor@other-corp.com","privilege":"SELECT"}]}]}`)
	if got.IssuesDetected != 0 {
		t.Fatalf("expected silence on ungroundable input, got %d issues", got.IssuesDetected)
	}
	joined := strings.ToLower(strings.Join(got.ChecksNotRun, " | "))
	for _, want := range []string{"org_domains", "last_used", "sensitive"} {
		if !strings.Contains(joined, want) {
			t.Errorf("response never mentions the skipped %s check; a caller would read 0 issues as clean.\ngot: %v",
				want, got.ChecksNotRun)
		}
	}
}

// The converse: when the estate DOES carry the grounding data, we must not nag about checks that ran.
// A caveat printed unconditionally is noise, and noise is how real caveats stop being read.
func TestDataPlatform_NoCaveatWhenFullyGrounded(t *testing.T) {
	h, _ := dpHandler(t)
	got := postEstate(t, h, `{
	  "org_domains":["acme.io"],
	  "objects":[{"platform":"snowflake","name":"db.public.t","type":"table","sensitive":true,
	    "grants":[{"grantee":"analyst_role","privilege":"SELECT","last_used":"2026-08-13"}]}]}`)
	if len(got.ChecksNotRun) != 0 {
		t.Errorf("every check could run, yet the response still caveats: %v", got.ChecksNotRun)
	}
}

func TestDataPlatform_RejectsGarbage(t *testing.T) {
	h, _ := dpHandler(t)
	if rec := do(h, "POST", "/v1/dataplatform/ingest", "t1", `{"objects":`); rec.Code != 400 {
		t.Errorf("malformed snapshot got %d, want 400", rec.Code)
	}
}

// Discovered sensitivity must reach the response AND drive the stored finding — the end-to-end proof
// that a crown jewel found in the data flows through the platform like a declared one.
func TestDataPlatform_DiscoversSensitivityFromSampledColumns(t *testing.T) {
	h, st := dpHandler(t)
	got := postEstate(t, h, `{
	  "objects":[{"platform":"snowflake","name":"prod.public.users","type":"table",
	    "columns":[{"name":"national_number","values":["123-45-6789","078-05-1120"]}],
	    "grants":[{"grantee":"PUBLIC","privilege":"SELECT"}]}]}`)
	if got.IssuesDetected != 1 {
		t.Fatalf("want the account-wide grant on discovered-sensitive data, got %d", got.IssuesDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Fatalf("discovered-sensitive account-wide grant should be high, got %+v", fs)
	}
}
