package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A live cloud read that cannot say what it covered is worse than no live read, because the result
// LOOKS current. Every response here carries coverage — especially the successful one.

type fetchLister struct {
	out []awsfetch.Bucket
	err error
}

func (f fetchLister) ListBuckets(context.Context) ([]awsfetch.Bucket, error) { return f.out, f.err }

func syncReq() (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/cloud/sync", nil)
}

func syncDeps(t *testing.T, lister awsfetch.BucketLister, withConn bool) Deps {
	t.Helper()
	st := store.NewMemory()
	if withConn {
		if err := st.PutConnection(context.Background(), platform.Connection{
			ID: "c-1", TenantID: "ten-1", Kind: platform.ConnAWS,
			Status: platform.ConnActive, Account: "123456789012",
			SecretRef: "arn:aws:iam::123456789012:role/tsengine-readonly",
		}); err != nil {
			t.Fatal(err)
		}
	}
	d := Deps{Store: st, CloudSnapshots: cloudsnap.NewMemStore()}
	if lister != nil {
		d.AWSFetcher = func(c platform.Connection) awsfetch.Fetcher {
			return awsfetch.Fetcher{AccountID: c.Account, Buckets: lister}
		}
	}
	return d
}

func TestCloudSync_SaysWhenLiveReadIsUnavailable(t *testing.T) {
	d := syncDeps(t, nil, true) // no fetcher wired
	rec, req := syncReq()
	d.handleCloudSync(rec, req, "ten-1")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "live_fetch_unavailable" {
		t.Errorf("no machine-readable reason: %v", body)
	}
	// It must point at what DOES work rather than leaving the customer stuck.
	if !strings.Contains(body["error"], "/v1/cloud/inventory") {
		t.Errorf("the refusal does not say what still works: %q", body["error"])
	}
}

func TestCloudSync_RefusesWithNoConnectedAccount(t *testing.T) {
	d := syncDeps(t, fetchLister{}, false) // fetcher wired, no connection
	rec, req := syncReq()
	d.handleCloudSync(rec, req, "ten-1")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no_aws_connection") {
		t.Errorf("no machine-readable reason: %s", rec.Body.String())
	}
}

// A FAILED read must read as a failure. Summarising an empty inventory here would be
// indistinguishable from an account with nothing in it.
func TestCloudSync_FailedReadIsNotAnEmptyAccount(t *testing.T) {
	d := syncDeps(t, fetchLister{err: errors.New("AccessDenied: s3:ListAllMyBuckets")}, true)
	rec, req := syncReq()
	d.handleCloudSync(rec, req, "ten-1")

	if rec.Code == http.StatusOK {
		t.Fatal("a failed AWS read returned 200 — the customer would read it as a clean account")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "AccessDenied") {
		t.Errorf("the underlying cause is not surfaced: %s", body)
	}
	if !strings.Contains(body, "coverage") {
		t.Errorf("even a failure must say what it covered: %s", body)
	}
}

// THE POINT: a successful sync still says what it did NOT read.
func TestCloudSync_SuccessStillReportsCoverage(t *testing.T) {
	d := syncDeps(t, fetchLister{out: []awsfetch.Bucket{{Name: "logs", Public: true}}}, true)
	rec, req := syncReq()
	d.handleCloudSync(rec, req, "ten-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	cov, _ := body["coverage"].(string)
	if cov == "" {
		t.Fatal("a successful sync reported no coverage — a partial inventory would pass for a whole one")
	}
	for _, unread := range []string{"iam", "ec2"} {
		if !strings.Contains(cov, unread) {
			t.Errorf("coverage does not name %q as unread: %q", unread, cov)
		}
	}
	// And it must have gone through the same path a posted inventory takes.
	if body["stored"] != true {
		t.Errorf("the fetched inventory was not stored: %v", body)
	}
	if _, ok := body["drift_detected"]; !ok {
		t.Error("the live path skipped drift detection — a posted inventory gets it, so the two " +
			"paths would report different things about the same account")
	}
}
