package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// hitServer counts POSTs per path, so one server can stand in for several channels.
type hitServer struct {
	mu   sync.Mutex
	hits map[string]int
	srv  *httptest.Server
}

func newHitServer(t *testing.T) *hitServer {
	h := &hitServer{hits: map[string]int{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[r.URL.Path]++
		h.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hitServer) count(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func highIncident() platform.Incident {
	return platform.Incident{ID: "inc-1", TenantID: "t1", Severity: "high", Title: "x", RuleID: "r"}
}

func TestBuildTenantChannels_OnlyConfigured(t *testing.T) {
	got := BuildTenantChannels(TenantSecrets{Teams: "https://x", PagerDutyKey: "k"}, nil)
	if len(got) != 2 || got["teams"] == nil || got["pagerduty"] == nil {
		t.Fatalf("want exactly teams+pagerduty, got %v", got)
	}
	if len(BuildTenantChannels(TenantSecrets{}, nil)) != 0 {
		t.Fatal("no secrets must yield no channels")
	}
}

// The generic webhook's host is chosen by the tenant, so it must not be able to reach a private
// address. httptest listens on loopback — exactly the class of address the guard exists to refuse.
func TestTenantWebhook_RefusesNonPublicHost(t *testing.T) {
	h := newHitServer(t)
	chans := BuildTenantChannels(TenantSecrets{WebhookURL: h.srv.URL + "/hook"}, nil) // nil → guarded client
	if err := chans["webhook"].IncidentOpened(context.Background(), highIncident()); err == nil {
		t.Fatal("a tenant webhook pointed at loopback must fail, not deliver")
	}
	if h.count("/hook") != 0 {
		t.Fatal("the guarded client reached a loopback address")
	}
}

func TestTenantRouter_DeliversEveryTenantChannelAndFallback(t *testing.T) {
	h := newHitServer(t)
	chans := BuildTenantChannels(TenantSecrets{
		Slack:      h.srv.URL + "/slack",
		Teams:      h.srv.URL + "/teams",
		Discord:    h.srv.URL + "/discord",
		WebhookURL: h.srv.URL + "/hook",
	}, h.srv.Client()) // test-only: a plain client so loopback is reachable
	chans["pagerduty"] = &PagerDuty{RoutingKey: "k", EventsURL: h.srv.URL + "/pd", HTTP: h.srv.Client()}
	op := &Webhook{URL: h.srv.URL + "/operator", MinSeverity: "all", HTTP: h.srv.Client()}

	r := TenantRouter{
		Channels: func(context.Context, string) map[string]Alerter { return chans },
		Fallback: op,
	}
	if err := r.IncidentOpened(context.Background(), highIncident()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/slack", "/teams", "/discord", "/hook", "/pd", "/operator"} {
		if h.count(p) != 1 {
			t.Errorf("%s: want 1 delivery, got %d", p, h.count(p))
		}
	}
}

// A tier naming "pagerduty" must page the TENANT's rotation when it has one — not ours.
func TestPolicyRouter_TenantChannelWinsOverOperator(t *testing.T) {
	h := newHitServer(t)
	tenantPD := &PagerDuty{RoutingKey: "tenant", EventsURL: h.srv.URL + "/tenant-pd", HTTP: h.srv.Client()}
	opPD := &PagerDuty{RoutingKey: "op", EventsURL: h.srv.URL + "/op-pd", HTTP: h.srv.Client()}
	opSlack := &Slack{WebhookURL: h.srv.URL + "/op-slack", HTTP: h.srv.Client()}

	pol := &platform.EscalationPolicy{Enabled: true, Tiers: []platform.EscalationTier{
		{MinSeverity: "high", Channels: []string{"pagerduty", "slack"}},
	}}
	r := PolicyRouter{
		Resolve:        func(context.Context, string) *platform.EscalationPolicy { return pol },
		Channels:       map[string]Alerter{"pagerduty": opPD, "slack": opSlack},
		TenantChannels: func(context.Context, string) map[string]Alerter { return map[string]Alerter{"pagerduty": tenantPD} },
	}
	if err := r.IncidentOpened(context.Background(), highIncident()); err != nil {
		t.Fatal(err)
	}
	if h.count("/tenant-pd") != 1 || h.count("/op-pd") != 0 {
		t.Errorf("tenant PD %d, operator PD %d — the tenant's rotation must be paged instead of ours",
			h.count("/tenant-pd"), h.count("/op-pd"))
	}
	// The tenant has no Slack of its own, so the operator's still serves that name.
	if h.count("/op-slack") != 1 {
		t.Errorf("operator slack should serve a name the tenant did not configure, got %d", h.count("/op-slack"))
	}
}
