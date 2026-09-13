package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type apiTrail struct{ page awsfetch.EventPage }

func (a apiTrail) LookupEvents(context.Context, time.Time, time.Time) (awsfetch.EventPage, error) {
	return a.page, nil
}

type capOpener struct{ got []types.Finding }

func (c *capOpener) OpenFor(_ context.Context, _ string, fs []types.Finding, _ map[string]bool) (detect.Result, error) {
	c.got = append(c.got, fs...)
	return detect.Result{}, nil
}

// The on-demand door is the pass's twin: same runner function, so a deployment without the poller
// says so (503), a read that found a root login stores it, returns it and opens the incident NOW,
// and a wired deployment with no readable account is 503 with the reasons, never "0 threats".
func TestCloudEventsSync_UnwiredSaysSoAndWiredReadsStoresAndOpens(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive, SecretRef: "arn:aws:iam::1:role/ro"})

	opener := &capOpener{}
	d := Deps{Store: st, IncidentOpener: opener}
	rec := httptest.NewRecorder()
	d.handleCloudEventsSync(rec, httptest.NewRequest(http.MethodPost, "/v1/cloud/events/sync", nil), "t1")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "cloudtrail_unavailable") {
		t.Fatalf("unwired must be 503 cloudtrail_unavailable, got %d %s", rec.Code, rec.Body.String())
	}

	root := `{"userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root"},"eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9"}`
	n := 0
	d.Runner = &runner.Service{Store: st, NewID: func() string { n++; return "f" + string(rune('0'+n)) },
		CloudEventReader: func(platform.Connection) awsfetch.EventReader {
			return apiTrail{page: awsfetch.EventPage{Records: [][]byte{[]byte(root)}, Latest: time.Now(), Oldest: time.Now()}}
		}}
	rec = httptest.NewRecorder()
	d.handleCloudEventsSync(rec, httptest.NewRequest(http.MethodPost, "/v1/cloud/events/sync", nil), "t1")
	if rec.Code != http.StatusOK {
		t.Fatalf("wired: %d %s", rec.Code, rec.Body.String())
	}
	var out runner.CloudEventResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Records != 1 || len(out.Connections) != 1 || len(out.Threats) != 1 || len(out.Findings) != 1 || out.Findings[0].RuleID != "cloudcdr::root_console_login" {
		t.Errorf("result: %+v", out)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 {
		t.Error("findings must be stored, not only returned")
	}
	if len(opener.got) != 1 {
		t.Errorf("the door must open the incident immediately like the posted-event door: %+v", opener.got)
	}

	// Wired, but the only AWS connection is not active → nothing read → 503 with reasons.
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnQuarantined})
	rec = httptest.NewRecorder()
	d.handleCloudEventsSync(rec, httptest.NewRequest(http.MethodPost, "/v1/cloud/events/sync", nil), "t1")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "cloudtrail_not_read") {
		t.Errorf("no account read must be 503 cloudtrail_not_read, got %d %s", rec.Code, rec.Body.String())
	}
}
