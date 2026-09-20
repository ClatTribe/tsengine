package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// blockingScanner does not return from Scan until released. It is how the test proves the callback
// no longer WAITS for the scan: if the redirect only arrives after release, the scan is still on the
// request path and the defect this file guards against has come back.
type blockingScanner struct {
	release chan struct{}
	started chan struct{}
}

func (b *blockingScanner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		// A cancelled context here means the scan was tied to the HTTP request's lifetime — the
		// exact bug: the browser navigates away and the first scan dies with it.
		return nil, ctx.Err()
	}
	return []types.Finding{{ID: "f1", RuleID: "r", Severity: "high", Endpoint: a.Target}}, nil
}

// The OAuth callback used to run DiscoverAndScan synchronously inside the provider redirect, so the
// browser sat on GitHub's redirect page for the whole scan and the edge timed out first. With a job
// pool the callback must (1) land the browser IMMEDIATELY with the job id in the URL, (2) run the scan
// on a context that outlives the request, and (3) record what it scanned on the job.
func TestConnectCallback_QueuesFirstScanAndRedirectsImmediately(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	sc := &blockingScanner{release: make(chan struct{}), started: make(chan struct{}, 1)}
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: sc}
	pool := jobs.NewPool(1, 4, 8, 0, func() string { return "job-connect-1" })
	defer func() { _ = pool.Shutdown(context.Background()) }()
	d := Deps{Store: st, Connectors: reg, Runner: svc, Vault: &recordingSealer{}, Jobs: pool, Token: "tok", PublicURL: "https://app", AppURL: "https://app.example"}
	h := NewHandler(d)

	// The request context is CANCELLED right after the handler returns — as it is in production when
	// the browser follows the 303. A scan still bound to it would fail with context.Canceled.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc&state="+url.QueryEscape(d.signOAuthState("t1")), nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { h.ServeHTTP(rec, req); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not return while the scan was still running — the scan is still on the request path")
	}
	cancel()

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d body %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example/assets?connected=github&job=job-connect-1") {
		t.Fatalf("redirect must carry the job id so the page can poll it, got %q", loc)
	}
	if strings.Contains(loc, "scanned=") {
		t.Fatalf("an async redirect must not claim a scanned count it does not have yet: %q", loc)
	}
	job, ok := pool.Get("job-connect-1")
	if !ok || job.TenantID != "t1" || job.Kind != "connect" {
		t.Fatalf("expected a tenant-scoped connect job, got %+v ok=%v", job, ok)
	}

	// Now let the scan finish and prove it ran to completion on its own context.
	select {
	case <-sc.started:
	case <-time.After(3 * time.Second):
		t.Fatal("the queued scan never started")
	}
	close(sc.release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, _ = pool.Get("job-connect-1")
		if job.Status == jobs.StatusDone || job.Status == jobs.StatusFailed || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.Status != jobs.StatusDone {
		t.Fatalf("job should complete after the scan is released, got status=%s err=%q", job.Status, job.Error)
	}
	res, _ := job.Result.(map[string]any)
	if res["assets_scanned"] != 1 {
		t.Fatalf("job result should record the scanned count, got %+v", job.Result)
	}
	if fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{}); len(fs) != 1 {
		t.Fatalf("the finding from the queued first scan must be persisted, got %d", len(fs))
	}
}

// Without a job pool the callback keeps today's synchronous behaviour and the redirect still carries
// the scanned count — non-browser callers and pool-less deployments are unchanged.
func TestConnectCallback_NoPoolStaysSynchronous(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	d := Deps{Store: st, Connectors: reg, Runner: svc, Vault: &recordingSealer{}, Token: "tok", PublicURL: "https://app", AppURL: "https://app.example"}
	h := NewHandler(d)
	req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc&state="+url.QueryEscape(d.signOAuthState("t1")), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "&scanned=1") || strings.Contains(loc, "job=") {
		t.Fatalf("pool-less callback should redirect with the synchronous scanned count, got %q", loc)
	}
}

// The first findings ever to land in a workspace are the activation event the free tier is built
// around, and nobody was told about them. The queued first scan emails the OWNER once — and only
// when the workspace went from no findings to some; a later connect on a workspace that already has
// findings sends nothing (monitoring has its own channels).
func TestConnectCallback_EmailsOwnerOnFirstFindingsOnce(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	pool := jobs.NewPool(1, 4, 8, 0, func() string { return "j" })
	defer func() { _ = pool.Shutdown(context.Background()) }()
	mailer := &captureMailer{}
	d := Deps{Store: st, Connectors: reg, Runner: svc, Vault: &recordingSealer{}, Jobs: pool, Mailer: mailer, Token: "tok", PublicURL: "https://app", AppURL: "https://app.example"}
	_ = st.PutUser(context.Background(), platform.User{ID: "u1", TenantID: "t1", Email: "founder@acme.io", Role: platform.RoleOwner})
	_ = st.PutUser(context.Background(), platform.User{ID: "u2", TenantID: "t1", Email: "dev@acme.io", Role: platform.RoleMember})
	h := NewHandler(d)

	connect := func() {
		req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc&state="+url.QueryEscape(d.signOAuthState("t1")), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("want 303, got %d %s", rec.Code, rec.Body.String())
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if j, _ := pool.Get("j"); j.Status == jobs.StatusDone || j.Status == jobs.StatusFailed {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("connect job did not finish")
	}
	connect()
	if mailer.sent != 1 || mailer.to != "founder@acme.io" || !strings.Contains(mailer.subject, "first findings") {
		t.Fatalf("the owner (and only the owner) must get the first-findings email once, got sent=%d to=%q subject=%q", mailer.sent, mailer.to, mailer.subject)
	}
	if !strings.Contains(mailer.body, "https://app.example/issues") {
		t.Fatalf("the email must link to the findings, got %q", mailer.body)
	}
	connect() // the workspace already has findings — monitoring, not activation
	if mailer.sent != 1 {
		t.Fatalf("a later scan must not re-send the activation email, got sent=%d", mailer.sent)
	}
}
