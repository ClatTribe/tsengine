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

func vercelHandler(t *testing.T) (http.Handler, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	return NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}), st
}

type vercelResp struct {
	Projects       int      `json:"projects"`
	IssuesDetected int      `json:"issues_detected"`
	ChecksNotRun   []string `json:"checks_not_run"`
}

func postVercel(t *testing.T, h http.Handler, body string) vercelResp {
	t.Helper()
	rec := do(h, "POST", "/v1/vercel/ingest", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("ingest = %d: %s", rec.Code, rec.Body.String())
	}
	var out vercelResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad response: %v", err)
	}
	return out
}

// End to end: an unprotected preview deployment becomes a stored finding that flows through the same
// machinery as everything else.
func TestVercelIngest_EndToEnd(t *testing.T) {
	h, st := vercelHandler(t)
	got := postVercel(t, h, `{"projects":[
	  {"name":"acme-web","preview_protected":false,"production_protected":false,"public_source":true}
	]}`)
	if got.Projects != 1 || got.IssuesDetected != 1 {
		t.Fatalf("projects=%d issues=%d, want 1/1", got.Projects, got.IssuesDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("stored %d findings, want 1", len(fs))
	}
	if fs[0].Tool != "vercelposture" {
		t.Errorf("tool = %q", fs[0].Tool)
	}
	if fs[0].Endpoint != "vercel:acme-web" {
		t.Errorf("endpoint = %q — a responder must be able to find the project", fs[0].Endpoint)
	}
}

// A well-configured account stores nothing. This is what makes a zero result trustworthy.
func TestVercelIngest_CleanAccountStoresNothing(t *testing.T) {
	h, st := vercelHandler(t)
	got := postVercel(t, h, `{"projects":[
	  {"name":"acme-web","preview_protected":true,"production_protected":false,"public_source":true}
	]}`)
	if got.IssuesDetected != 0 {
		t.Errorf("a well-configured account reported %d issues", got.IssuesDetected)
	}
	if fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{}); len(fs) != 0 {
		t.Errorf("stored %d findings for a clean account", len(fs))
	}
}

// THE HONESTY THAT HAS TO REACH THE WIRE. The assessor stays silent on settings a snapshot did not
// carry (absent config is not insecure config). But a caller who sees "0 issues" and is not told
// WHICH projects went unjudged will read it as a clean account — the exact false assurance the
// refusal exists to prevent.
func TestVercelIngest_NamesProjectsItCouldNotJudge(t *testing.T) {
	h, _ := vercelHandler(t)
	got := postVercel(t, h, `{"projects":[{"name":"mystery-app"}]}`)
	if got.IssuesDetected != 0 {
		t.Fatalf("expected silence on an incomplete export, got %d issues", got.IssuesDetected)
	}
	joined := strings.Join(got.ChecksNotRun, " ")
	if !strings.Contains(joined, "mystery-app") {
		t.Errorf("the response does not name the unjudged project: %v", got.ChecksNotRun)
	}
	if !strings.Contains(strings.ToLower(joined), "not a clean bill of health") {
		t.Errorf("the response lets 0 issues read as clean: %v", got.ChecksNotRun)
	}
}

// The converse: a complete snapshot must not carry a caveat. A warning that always fires is noise,
// and noise is how real warnings stop being read.
func TestVercelIngest_NoCaveatWhenTheExportIsComplete(t *testing.T) {
	h, _ := vercelHandler(t)
	got := postVercel(t, h, `{"projects":[
	  {"name":"acme-web","preview_protected":true,"production_protected":true,"public_source":true}
	]}`)
	if len(got.ChecksNotRun) != 0 {
		t.Errorf("a complete export still produced a caveat: %v", got.ChecksNotRun)
	}
}

func TestVercelIngest_RejectsGarbage(t *testing.T) {
	h, _ := vercelHandler(t)
	if rec := do(h, "POST", "/v1/vercel/ingest", "t1", `{"projects":`); rec.Code != 400 {
		t.Errorf("malformed snapshot got %d, want 400", rec.Code)
	}
}
