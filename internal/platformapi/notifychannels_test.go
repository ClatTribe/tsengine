package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	teamsHook = "https://acme.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi"
	pdKey     = "0123456789abcdef0123456789ABCDEF"
	slackHook = "https://hooks.slack.com/services/T000/B000/XXXXsecretXXXX"
)

func TestNotifyChannels_SealPresenceNeverEcho(t *testing.T) {
	d, st := notifyDeps(t)
	rec := putNotify(d, `{"teams_webhook":"`+teamsHook+`","pagerduty_routing_key":"`+pdKey+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT %d: %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{teamsHook, pdKey} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("response echoed a destination: %s", rec.Body.String())
		}
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if strings.Contains(tn.NotifyChannelRefs["teams"], "webhook.office.com") || strings.Contains(tn.NotifyChannelRefs["pagerduty"], pdKey) {
		t.Fatal("destinations must be stored sealed")
	}
	if tn.Redacted().NotifyChannelRefs != nil {
		t.Fatal("Redacted() must strip the channel refs")
	}
	got := tn.NotifyChannelsConfigured()
	if !got["teams"] || !got["pagerduty"] || got["slack"] || got["webhook"] {
		t.Fatalf("presence wrong: %v", got)
	}
}

// The original endpoint cleared Slack on an empty body. A client that sends only Teams must not
// silently wipe the Slack hook the customer set last month.
func TestNotifyChannels_AbsentFieldLeavesChannelAlone(t *testing.T) {
	d, st := notifyDeps(t)
	if rec := putNotify(d, `{"slack_webhook":"`+slackHook+`"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := putNotify(d, `{"teams_webhook":"`+teamsHook+`"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if !tn.HasSlackWebhook() {
		t.Fatal("setting Teams cleared Slack")
	}
	if rec := putNotify(d, `{"teams_webhook":""}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	tn, _ = st.GetTenant(context.Background(), "ten-1")
	if tn.NotifyChannelsConfigured()["teams"] || !tn.HasSlackWebhook() {
		t.Fatalf("an explicit empty string clears only that channel: %v", tn.NotifyChannelsConfigured())
	}
}

func TestNotifyChannels_RejectsUndeliverableWithoutHalfApplying(t *testing.T) {
	d, st := notifyDeps(t)
	cases := []string{
		`{"teams_webhook":"https://evil.example.com/hook"}`,
		`{"teams_webhook":"http://acme.webhook.office.com/x"}`,
		`{"pagerduty_routing_key":"short"}`,
		`{"discord_webhook":"https://example.com/api/webhooks/1"}`,
		`{"webhook_url":"http://hooks.example.com/x"}`,
		`{"webhook_url":"https://localhost/x"}`,
		`{"webhook_url":"https://169.254.169.254/latest/meta-data"}`,
		`{"webhook_url":"https://10.0.0.5/x"}`,
		`{"webhook_secret":"tooshort"}`,
		`{"sms_number":"+15555550100"}`,
		// one good field + one bad: nothing may be stored
		`{"teams_webhook":"` + teamsHook + `","pagerduty_routing_key":"short"}`,
	}
	for _, c := range cases {
		if rec := putNotify(d, c); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", c, rec.Code, rec.Body.String())
		}
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if len(tn.NotifyChannelRefs) != 0 {
		t.Fatalf("a rejected request stored something: %v", tn.NotifyChannelRefs)
	}
}

func TestNotifyChannels_SecretDroppedWithItsWebhook(t *testing.T) {
	d, st := notifyDeps(t)
	if rec := putNotify(d, `{"webhook_url":"https://hooks.example.com/ts","webhook_secret":"0123456789abcdefXYZ"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := putNotify(d, `{"webhook_url":""}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.NotifyChannelRefs["webhook_secret"] != "" {
		t.Fatal("a signing secret with no webhook left behind")
	}
}

func testNotify(d Deps, channel string) map[string]any {
	req := httptest.NewRequest(http.MethodPost, "/v1/settings/notifications/test", strings.NewReader(`{"channel":"`+channel+`"}`))
	rec := httptest.NewRecorder()
	d.handleTestNotifyChannel(rec, req, "ten-1")
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	out["_code"] = rec.Code
	return out
}

func TestNotifyChannels_TestSendReportsTheTruth(t *testing.T) {
	d, st := notifyDeps(t)
	var hits atomic.Int32
	var gotTitle atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		gotTitle.Store(b["title"])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer broken.Close()

	// Not configured → refused, nothing sent.
	if out := testNotify(d, "webhook"); out["_code"] != http.StatusBadRequest {
		t.Fatalf("testing an unconfigured channel must be refused, got %v", out)
	}
	// Point the tenant's webhook at the local server directly (save-time validation would rightly
	// refuse loopback), and let the test reach it.
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	ref, _ := d.Vault.Seal(srv.URL + "/hook")
	tn.NotifyChannelRefs = map[string]string{"webhook": ref}
	_ = st.PutTenant(context.Background(), tn)
	testChannelHTTP = srv.Client()
	defer func() { testChannelHTTP = nil }()

	out := testNotify(d, "webhook")
	if out["ok"] != true || hits.Load() != 1 {
		t.Fatalf("want one delivered test, got %v hits=%d", out, hits.Load())
	}
	if title, _ := gotTitle.Load().(string); !strings.Contains(title, "[TEST]") {
		t.Fatalf("a test alert must say it is a test, got %q", title)
	}

	// A destination that answers with an error must be reported as failed, not as sent.
	ref, _ = d.Vault.Seal(broken.URL + "/hook")
	tn.NotifyChannelRefs = map[string]string{"webhook": ref}
	_ = st.PutTenant(context.Background(), tn)
	if out := testNotify(d, "webhook"); out["ok"] != false || out["error"] == "" {
		t.Fatalf("a 410 from the destination must report ok:false with the error, got %v", out)
	}
}

func TestNotifyChannelResolver_OpensWhatIsConfigured(t *testing.T) {
	d, st := notifyDeps(t)
	if rec := putNotify(d, `{"slack_webhook":"`+slackHook+`","pagerduty_routing_key":"`+pdKey+`"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	chans := NotifyChannelResolver(st, d.Vault)(context.Background(), "ten-1")
	if len(chans) != 2 || chans["slack"] == nil || chans["pagerduty"] == nil {
		t.Fatalf("want slack+pagerduty, got %v", chans)
	}
	if got := NotifyChannelResolver(st, d.Vault)(context.Background(), "nobody"); len(got) != 0 {
		t.Fatal("an unknown tenant must yield no channels")
	}
}
