package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// razorpay.go is the India payment adapter. Razorpay (not Stripe) because the buyer is an Indian SMB:
// UPI + netbanking are table stakes and Stripe is restricted for Indian entities.
//
// The split, as everywhere else in this codebase: VerifyWebhook + ParseEvent are PURE and fully
// tested (they need no account); CreateOrder is the live, credential-gated half. No keys → the
// checkout endpoint says so honestly instead of pretending.

// Razorpay holds the operator's API credentials. Zero value = not configured (checkout refuses).
type Razorpay struct {
	KeyID         string // rzp_live_… / rzp_test_… — public, safe to hand the browser
	KeySecret     string // NEVER leaves the server
	WebhookSecret string // shared secret for X-Razorpay-Signature
	APIBase       string // default https://api.razorpay.com
	HTTP          *http.Client
}

// Configured reports whether live calls can be made. Checkout is gated on this.
func (r *Razorpay) Configured() bool { return r != nil && r.KeyID != "" && r.KeySecret != "" }

func (r *Razorpay) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (r *Razorpay) base() string {
	if r.APIBase != "" {
		return strings.TrimRight(r.APIBase, "/")
	}
	return "https://api.razorpay.com"
}

// VerifyWebhook checks Razorpay's X-Razorpay-Signature: hex(HMAC-SHA256(raw_body, webhook_secret)).
//
// FAILS CLOSED — this is the function standing between a stranger and a free Enterprise plan:
// no secret configured → false; malformed/absent signature → false; constant-time compare.
func VerifyWebhook(body []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	// hmac.Equal is constant-time; compare the decoded bytes so casing/length can't leak timing.
	return hmac.Equal([]byte(strings.TrimSpace(signature)), []byte(want))
}

// rzpWebhook is the slice of Razorpay's webhook envelope we rely on. We read our OWN notes (set at
// checkout) rather than trusting any provider-side plan naming.
type rzpWebhook struct {
	Event   string `json:"event"`
	Payload struct {
		Payment struct {
			Entity struct {
				ID     string            `json:"id"`
				Status string            `json:"status"`
				Notes  map[string]string `json:"notes"`
			} `json:"entity"`
		} `json:"payment"`
		Subscription struct {
			Entity struct {
				ID    string            `json:"id"`
				Notes map[string]string `json:"notes"`
			} `json:"entity"`
		} `json:"subscription"`
	} `json:"payload"`
}

// ParseEvent normalises a VERIFIED webhook body into our Event. Pure.
//
// We act ONLY on money actually captured (payment.captured / subscription.charged) and on a real
// cancellation/halt — never on `payment.authorized` (an intent that may never capture) or
// `order.paid` alone. Identity comes from OUR notes, so an event can only touch the tenant that
// started that checkout.
func ParseEvent(body []byte) (Event, error) {
	var w rzpWebhook
	if err := json.Unmarshal(body, &w); err != nil {
		return Event{}, fmt.Errorf("billing: parse webhook: %w", err)
	}
	notes := w.Payload.Payment.Entity.Notes
	ref := w.Payload.Payment.Entity.ID
	if len(notes) == 0 {
		notes = w.Payload.Subscription.Entity.Notes
		ref = w.Payload.Subscription.Entity.ID
	}
	e := Event{
		Kind:     Ignored,
		TenantID: notes["tenant_id"],
		Plan:     notes["plan"],
		Cycle:    Cycle(notes["cycle"]),
		Ref:      ref,
	}
	switch w.Event {
	case "payment.captured", "subscription.charged":
		e.Kind = Paid
	case "subscription.cancelled", "subscription.halted", "subscription.completed":
		e.Kind = Cancelled
	}
	// A paid event we can't attribute to a tenant is useless and must never be applied blindly.
	if e.Kind != Ignored && e.TenantID == "" {
		return e, fmt.Errorf("billing: %s event carries no tenant_id note — refusing to guess", w.Event)
	}
	return e, nil
}

// Order is what the browser needs to open Razorpay Checkout.
type Order struct {
	OrderID    string  `json:"order_id"`
	KeyID      string  `json:"key_id"` // public
	Amounts    Amounts `json:"amounts"`
	Descriptor string  `json:"descriptor"`
}

// CreateOrder makes a real Razorpay order for a plan+cycle, stamping the tenant identity into notes
// so the webhook can attribute the payment back. The LIVE, credential-gated half.
func (r *Razorpay) CreateOrder(ctx context.Context, tenantID string, it Item) (Order, error) {
	if !r.Configured() {
		return Order{}, fmt.Errorf("billing: Razorpay is not configured (set RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET)")
	}
	amt := it.Price()
	body, _ := json.Marshal(map[string]any{
		"amount":   amt.TotalPaise, // Razorpay charges the GST-inclusive total
		"currency": amt.Currency,
		"receipt":  "ts-" + tenantID + "-" + string(it.Cycle),
		"notes": map[string]string{ // our identity round-trip — the webhook reads these back
			"tenant_id": tenantID,
			"plan":      it.Plan,
			"cycle":     string(it.Cycle),
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base()+"/v1/orders", bytes.NewReader(body))
	if err != nil {
		return Order{}, err
	}
	req.SetBasicAuth(r.KeyID, r.KeySecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		return Order{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Order{}, fmt.Errorf("billing: create order: HTTP %d", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ID == "" {
		return Order{}, fmt.Errorf("billing: create order returned no id")
	}
	return Order{OrderID: out.ID, KeyID: r.KeyID, Amounts: amt, Descriptor: it.Descriptor}, nil
}
