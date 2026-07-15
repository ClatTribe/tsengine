package platformapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/billing"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func billingDeps(t *testing.T, secret string) (Deps, store.Store) {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1", Name: "Acme", Plan: platform.PlanFree}); err != nil {
		t.Fatal(err)
	}
	return Deps{
		Store:    st,
		Token:    "ptok",
		NewID:    func() string { return "id-1" },
		Razorpay: &billing.Razorpay{KeyID: "rzp_test_k", KeySecret: "s", WebhookSecret: secret},
	}, st
}

func sign(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func paidBody(tenant string) []byte {
	return []byte(`{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_1","notes":{"tenant_id":"` +
		tenant + `","plan":"growth","cycle":"monthly"}}}}}`)
}

func post(h http.Handler, body []byte, sig string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook", strings.NewReader(string(body)))
	if sig != "" {
		r.Header.Set("X-Razorpay-Signature", sig)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestWebhook_SignedPaymentUpgradesTheTenant — the happy path that makes the business exist.
func TestWebhook_SignedPaymentUpgradesTheTenant(t *testing.T) {
	d, st := billingDeps(t, "whsec")
	h := NewHandler(d)
	body := paidBody("ten-1")
	w := post(h, body, sign(body, "whsec"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.Plan != platform.PlanGrowth {
		t.Errorf("a captured payment must upgrade the tenant, got plan=%q", tn.Plan)
	}
	// Paying must actually unlock what the pricing page sold on Core.
	before, after := platform.Entitlements(platform.PlanFree), platform.Entitlements(tn.Plan)
	if after.MaxAssets != 25 || before.MaxAssets != 2 {
		t.Errorf("Core must lift the target cap 2→25, got %d→%d", before.MaxAssets, after.MaxAssets)
	}
	if !after.AllFrameworks || !after.ContinuousMonitoring || !after.HumanInLoopApply {
		t.Errorf("Core must unlock frameworks/monitoring/approvals: %+v", after)
	}
	// NOT a bug: AIEnabled stays false on Core by design — it gates the OPERATOR-funded model only.
	// Core runs the agents on the tenant's OWN key (resolveAgentLLM allows that on any plan), which is
	// exactly what the pricing page sells. Enterprise is the tier where we fund the model.
	if after.AIEnabled {
		t.Error("Core must not enable OPERATOR-funded AI — that is the Enterprise tier")
	}
}

// TestWebhook_UnsignedCannotUpgrade is THE security test: without it, anyone on the internet could
// POST themselves a paid plan.
func TestWebhook_UnsignedCannotUpgrade(t *testing.T) {
	for _, c := range []struct{ name, sig string }{
		{"no signature", ""},
		{"wrong signature", "deadbeef"},
		{"signed with the wrong secret", sign(paidBody("ten-1"), "attacker")},
	} {
		d, st := billingDeps(t, "whsec")
		w := post(NewHandler(d), paidBody("ten-1"), c.sig)
		if w.Code == http.StatusOK {
			t.Errorf("%s: must NOT be accepted (got 200)", c.name)
		}
		tn, _ := st.GetTenant(context.Background(), "ten-1")
		if tn.Plan != platform.PlanFree {
			t.Errorf("%s: tenant was upgraded without a valid signature — plan=%q", c.name, tn.Plan)
		}
	}
}

// TestWebhook_TamperedBodyRejected: a valid signature for a DIFFERENT body must not carry over.
func TestWebhook_TamperedBodyRejected(t *testing.T) {
	d, st := billingDeps(t, "whsec")
	good := paidBody("ten-1")
	sig := sign(good, "whsec")
	tampered := paidBody("ten-1")
	tampered = []byte(strings.Replace(string(tampered), `"plan":"growth"`, `"plan":"enterprise"`, 1))
	w := post(NewHandler(d), tampered, sig)
	if w.Code == http.StatusOK {
		t.Error("a tampered body must be rejected")
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.Plan != platform.PlanFree {
		t.Errorf("tampered body changed the plan to %q", tn.Plan)
	}
}

// TestWebhook_NoSecretFailsClosed: an unconfigured deployment must not accept plan changes.
func TestWebhook_NoSecretFailsClosed(t *testing.T) {
	d, st := billingDeps(t, "") // no webhook secret
	body := paidBody("ten-1")
	w := post(NewHandler(d), body, sign(body, "whsec"))
	if w.Code == http.StatusOK {
		t.Error("no configured secret must fail closed, not accept")
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.Plan != platform.PlanFree {
		t.Error("plan changed with no webhook secret configured")
	}
}

// TestWebhook_AuthorizedIsNotPaid: an intent must never grant a plan.
func TestWebhook_AuthorizedIsNotPaid(t *testing.T) {
	d, st := billingDeps(t, "whsec")
	body := []byte(`{"event":"payment.authorized","payload":{"payment":{"entity":{"id":"p1","notes":{"tenant_id":"ten-1","plan":"growth","cycle":"monthly"}}}}}`)
	w := post(NewHandler(d), body, sign(body, "whsec"))
	if w.Code != http.StatusOK {
		t.Fatalf("want a 200 ack, got %d", w.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["applied"] != false {
		t.Error("payment.authorized must be acknowledged but NOT applied")
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.Plan != platform.PlanFree {
		t.Error("an authorization (not a capture) upgraded the plan")
	}
}

// TestWebhook_CancellationDowngrades: when the money stops, so does the plan.
func TestWebhook_CancellationDowngrades(t *testing.T) {
	d, st := billingDeps(t, "whsec")
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1", Name: "Acme", Plan: platform.PlanGrowth})
	body := []byte(`{"event":"subscription.cancelled","payload":{"subscription":{"entity":{"id":"sub1","notes":{"tenant_id":"ten-1","plan":"growth","cycle":"monthly"}}}}}`)
	w := post(NewHandler(d), body, sign(body, "whsec"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	tn, _ := st.GetTenant(context.Background(), "ten-1")
	if tn.Plan != platform.PlanFree {
		t.Errorf("a cancellation must return the tenant to free, got %q", tn.Plan)
	}
}

// TestWebhook_CannotTouchAnotherTenant: identity comes from the notes we stamped at checkout.
func TestWebhook_CannotTouchAnotherTenant(t *testing.T) {
	d, st := billingDeps(t, "whsec")
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "victim", Name: "V", Plan: platform.PlanFree})
	body := paidBody("nonexistent")
	w := post(NewHandler(d), body, sign(body, "whsec"))
	if w.Code == http.StatusOK {
		t.Error("an unknown tenant must not be accepted")
	}
	v, _ := st.GetTenant(context.Background(), "victim")
	if v.Plan != platform.PlanFree {
		t.Error("another tenant was affected")
	}
}
