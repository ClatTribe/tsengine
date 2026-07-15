package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestPrice_MatchesThePricingPage: the catalog must be the page, to the paise. ₹7,999 + 18% GST =
// ₹9,438.82; ₹79,990 + 18% = ₹94,388.20.
func TestPrice_MatchesThePricingPage(t *testing.T) {
	m, err := Lookup(platform.PlanGrowth, Monthly)
	if err != nil {
		t.Fatal(err)
	}
	got := m.Price()
	if got.BasePaise != 799900 || got.GSTPaise != 143982 || got.TotalPaise != 943882 {
		t.Errorf("monthly: %+v", got)
	}
	if got.Currency != "INR" || got.GSTRate != 18 {
		t.Errorf("must be ₹-native at 18%% GST: %+v", got)
	}
	a, err := Lookup(platform.PlanGrowth, Annual)
	if err != nil {
		t.Fatal(err)
	}
	if p := a.Price(); p.BasePaise != 7999000 || p.GSTPaise != 1439820 || p.TotalPaise != 9438820 {
		t.Errorf("annual: %+v", p)
	}
}

// TestLookup_EnterpriseIsNotSelfServe: Enterprise is talk-to-us. Nobody buys it with a card.
func TestLookup_EnterpriseIsNotSelfServe(t *testing.T) {
	if _, err := Lookup(platform.PlanEnterprise, Monthly); err == nil {
		t.Error("Enterprise must not be self-serve purchasable")
	}
	if _, err := Lookup(platform.PlanFree, Monthly); err == nil {
		t.Error("Free is not a purchase")
	}
	if _, err := Lookup(platform.PlanGrowth, Cycle("weekly")); err == nil {
		t.Error("an invented cycle must not resolve to a price")
	}
}

func TestRupees(t *testing.T) {
	for _, c := range []struct {
		paise int64
		want  string
	}{
		{943882, "₹9,438.82"},
		{9438820, "₹94,388.20"},
		{799900, "₹7,999.00"},
		{0, "₹0.00"},
	} {
		if got := Rupees(c.paise); got != c.want {
			t.Errorf("Rupees(%d) = %s, want %s", c.paise, got, c.want)
		}
	}
}

// TestVerifyWebhook_FailsClosed is the security test: this function is what stands between a stranger
// and a free paid plan.
func TestVerifyWebhook_FailsClosed(t *testing.T) {
	body := []byte(`{"event":"payment.captured"}`)
	secret := "whsec_abc"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	good := hex.EncodeToString(mac.Sum(nil))

	if !VerifyWebhook(body, good, secret) {
		t.Error("a correctly signed body must verify")
	}
	if VerifyWebhook(body, good, "") {
		t.Error("NO SECRET CONFIGURED MUST REJECT — never accept an unverifiable plan upgrade")
	}
	if VerifyWebhook(body, "", secret) {
		t.Error("missing signature must reject")
	}
	if VerifyWebhook(body, "deadbeef", secret) {
		t.Error("wrong signature must reject")
	}
	if VerifyWebhook([]byte(`{"event":"payment.captured","tampered":true}`), good, secret) {
		t.Error("a tampered body must reject")
	}
}

// TestParseEvent_OnlyActsOnCapturedMoney: an intent is not a payment.
func TestParseEvent_OnlyActsOnCapturedMoney(t *testing.T) {
	notes := `"notes":{"tenant_id":"ten-1","plan":"growth","cycle":"monthly"}`
	captured := []byte(`{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_1",` + notes + `}}}}`)
	e, err := ParseEvent(captured)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != Paid || e.TenantID != "ten-1" || e.Plan != "growth" || e.Cycle != Monthly || e.Ref != "pay_1" {
		t.Errorf("captured: %+v", e)
	}
	authorized := []byte(`{"event":"payment.authorized","payload":{"payment":{"entity":{"id":"pay_2",` + notes + `}}}}`)
	e2, err := ParseEvent(authorized)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Kind != Ignored {
		t.Error("payment.authorized is an INTENT, not money — must not grant a plan")
	}
	cancelled := []byte(`{"event":"subscription.cancelled","payload":{"subscription":{"entity":{"id":"sub_1",` + notes + `}}}}`)
	e3, err := ParseEvent(cancelled)
	if err != nil {
		t.Fatal(err)
	}
	if e3.Kind != Cancelled || e3.TenantID != "ten-1" {
		t.Errorf("cancelled: %+v", e3)
	}
}

// TestParseEvent_RefusesUnattributable: a paid event with no tenant note must error, not guess.
func TestParseEvent_RefusesUnattributable(t *testing.T) {
	body := []byte(`{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_x","notes":{}}}}}`)
	if _, err := ParseEvent(body); err == nil {
		t.Error("a paid event with no tenant_id must be an error, never applied to some tenant")
	}
}

// TestPlanAfter: the grant/revoke decision, including refusing a webhook that claims Enterprise.
func TestPlanAfter(t *testing.T) {
	if p, ok := PlanAfter(Event{Kind: Paid, Plan: "growth", Cycle: Monthly}); !ok || p != platform.PlanGrowth {
		t.Errorf("paid growth → growth, got %q %v", p, ok)
	}
	if p, ok := PlanAfter(Event{Kind: Cancelled}); !ok || p != platform.PlanFree {
		t.Errorf("cancelled → free, got %q %v", p, ok)
	}
	if _, ok := PlanAfter(Event{Kind: Ignored, Plan: "growth", Cycle: Monthly}); ok {
		t.Error("an ignored event must not change the plan")
	}
	// the important one: a webhook cannot mint a plan the catalog doesn't sell
	if _, ok := PlanAfter(Event{Kind: Paid, Plan: "enterprise", Cycle: Monthly}); ok {
		t.Error("a webhook claiming Enterprise must be refused — it is not self-serve")
	}
	if _, ok := PlanAfter(Event{Kind: Paid, Plan: "growth", Cycle: Cycle("weekly")}); ok {
		t.Error("a webhook with an uncatalogued cycle must be refused")
	}
}

// TestRazorpay_ConfiguredGate: no keys → checkout refuses honestly rather than pretending.
func TestRazorpay_ConfiguredGate(t *testing.T) {
	if (&Razorpay{}).Configured() {
		t.Error("zero value must not be configured")
	}
	if (&Razorpay{KeyID: "rzp_test_x"}).Configured() {
		t.Error("key id alone is not configured")
	}
	if !(&Razorpay{KeyID: "rzp_test_x", KeySecret: "s"}).Configured() {
		t.Error("id+secret is configured")
	}
	var r *Razorpay
	if r.Configured() {
		t.Error("nil must not be configured")
	}
}
