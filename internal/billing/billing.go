// Package billing is the plan lifecycle: how a tenant becomes (and stops being) a paying customer.
//
// Before this, `Tenant.Plan` was written in exactly two places — operator provisioning and signup's
// hardcoded "free" — and NOTHING ever changed it. A customer could read ₹7,999/mo on the pricing page,
// click through, and land on Free forever: the product could not take money.
//
// Shape follows the rest of the codebase: the DECISION layer here is pure + fully tested (catalog,
// GST, signature verification, event→plan), and the live provider call is the credential-gated half
// (razorpay.go). Razorpay because the buyer is an Indian SMB — UPI/netbanking are table stakes and
// Stripe is restricted for Indian entities.
//
// SECURITY: this package decides who gets a PAID plan, so the webhook path fails CLOSED. No secret
// configured → reject. Bad signature → reject. An unverified body can never grant a plan (otherwise
// anyone could POST themselves Enterprise).
package billing

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Cycle is the billing period.
type Cycle string

const (
	Monthly Cycle = "monthly"
	Annual  Cycle = "annual"
)

// GSTRate is India's GST on SaaS, in percent. The pricing page quotes ex-GST ("₹7,999 / month + GST"),
// so this is ADDED to the base — it is not extracted from it.
const GSTRate = 18

// Item is one sellable plan+cycle and its ex-GST price in paise (₹1 = 100 paise; integers only —
// never float money).
type Item struct {
	Plan       string // platform.PlanGrowth | platform.PlanEnterprise
	Cycle      Cycle
	BasePaise  int64  // ex-GST
	Descriptor string // what appears on the invoice line
}

// Catalog is what a customer can actually buy self-serve. It mirrors the pricing page 1:1 — Core
// (plan key "growth") at ₹7,999/mo or ₹79,990/yr. Enterprise is deliberately absent: it is
// talk-to-us, provisioned by an operator, never a self-serve checkout.
var Catalog = []Item{
	{Plan: platform.PlanGrowth, Cycle: Monthly, BasePaise: 799900, Descriptor: "TensorShield Core — monthly"},
	{Plan: platform.PlanGrowth, Cycle: Annual, BasePaise: 7999000, Descriptor: "TensorShield Core — annual"},
}

// Lookup finds a sellable item. An unknown plan/cycle is an error — we never invent a price.
func Lookup(plan string, cycle Cycle) (Item, error) {
	p := platform.NormalizePlan(plan)
	for _, it := range Catalog {
		if it.Plan == p && it.Cycle == cycle {
			return it, nil
		}
	}
	return Item{}, fmt.Errorf("billing: %q on a %s cycle is not self-serve purchasable", plan, cycle)
}

// Amounts is the money breakdown for an invoice, all in paise.
type Amounts struct {
	BasePaise  int64  `json:"base_paise"`
	GSTPaise   int64  `json:"gst_paise"`
	TotalPaise int64  `json:"total_paise"`
	GSTRate    int    `json:"gst_rate"`
	Currency   string `json:"currency"` // always INR — the catalog is ₹-native
}

// Price computes base + GST. Integer paise throughout; GST rounds half-up to the paise, which is what
// an Indian tax invoice requires.
func (it Item) Price() Amounts {
	gst := (it.BasePaise*int64(GSTRate) + 50) / 100
	return Amounts{
		BasePaise: it.BasePaise, GSTPaise: gst, TotalPaise: it.BasePaise + gst,
		GSTRate: GSTRate, Currency: "INR",
	}
}

// Rupees renders paise for display ("₹9,438.82"). Presentation only — never used for math.
func Rupees(paise int64) string {
	neg := paise < 0
	if neg {
		paise = -paise
	}
	whole, frac := paise/100, paise%100
	s := groupIndian(whole)
	out := fmt.Sprintf("₹%s.%02d", s, frac)
	if neg {
		out = "-" + out
	}
	return out
}

// groupIndian formats with the Indian digit grouping (last 3, then pairs): 7999000 → "79,99,000".
func groupIndian(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	head, tail := s[:len(s)-3], s[len(s)-3:]
	var parts []string
	for len(head) > 2 {
		parts = append([]string{head[len(head)-2:]}, parts...)
		head = head[:len(head)-2]
	}
	if head != "" {
		parts = append([]string{head}, parts...)
	}
	return strings.Join(parts, ",") + "," + tail
}

// EventKind is the subset of provider events that move a plan. Anything else is ignored (we act on
// money actually captured, never on an intent).
type EventKind string

const (
	// Paid — the customer's money was captured for a cycle → grant the plan.
	Paid EventKind = "paid"
	// Cancelled — the subscription ended/lapsed → fall back to Free.
	Cancelled EventKind = "cancelled"
	// Ignored — an event we deliberately do not act on.
	Ignored EventKind = "ignored"
)

// Event is a provider event normalised into our terms. TenantID/Plan ride the provider's `notes`,
// which we set at checkout — so a webhook can only ever affect the tenant that started the checkout.
type Event struct {
	Kind     EventKind
	TenantID string
	Plan     string
	Cycle    Cycle
	Ref      string // provider payment/subscription id — the audit trail
}

// PlanAfter returns the plan a tenant should hold after this event, and whether it changes anything.
// Grounded: only a captured payment grants a paid plan; a cancellation returns to Free; anything else
// is a no-op. It never upgrades on an unverified or unknown event.
func PlanAfter(e Event) (string, bool) {
	switch e.Kind {
	case Paid:
		p := platform.NormalizePlan(e.Plan)
		// Self-serve can only buy what the catalog sells — a webhook claiming "enterprise" is refused.
		if _, err := Lookup(p, e.Cycle); err != nil {
			return "", false
		}
		return p, true
	case Cancelled:
		return platform.PlanFree, true
	default:
		return "", false
	}
}
