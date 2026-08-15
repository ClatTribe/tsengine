package hitl

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A delivery failure has to be VISIBLE, and it has to be visible without leaking a credential.
//
// Desk.apply deliberately leaves a failed action at ActApproved rather than dropping it. That is the
// right call — a lost action is worse than a stuck one — but it means the actions list showed a failed
// delivery and a not-yet-delivered action identically. A customer whose Jira token had expired saw
// "approved", went looking in Jira, found nothing, and had nowhere to learn why.
//
// The catch is that the error text is the natural place to record, and delivery errors quote the
// endpoint they failed to reach. For Slack that endpoint IS the bearer credential.

// erroringApplier fails with a caller-supplied error.
type erroringApplier struct{ err error }

func (e *erroringApplier) Apply(context.Context, platform.Action) error { return e.err }

// togglingApplier fails until told to stop — a retry that succeeds.
type togglingApplier struct{ fail bool }

func (t *togglingApplier) Apply(context.Context, platform.Action) error {
	if t.fail {
		return errors.New("jira: 401 unauthorized")
	}
	return nil
}

func approveTier2(t *testing.T, d *Desk, st interface {
	PutAction(context.Context, platform.Action) error
}, id string) platform.Action {
	t.Helper()
	ctx := context.Background()
	_ = st.PutAction(ctx, platform.Action{
		ID: id, TenantID: "t", Tier: 2, Kind: platform.ActFileTicket,
		Status: platform.ActPendingApproval,
	})
	got, _ := d.Decide(ctx, "t", id, Verdict{Approver: "boss@acme.com", Approve: true})
	return got
}

// The failure is recorded on the action, where the customer looks.
func TestFailedDelivery_IsRecordedOnTheAction(t *testing.T) {
	d, _, st := newDesk(&erroringApplier{err: errors.New("jira: 401 unauthorized")})
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t", Name: "Acme"})

	got := approveTier2(t, d, st, "a1")
	if got.DeliveryError == "" {
		t.Fatal("a failed apply left no explanation — the action is indistinguishable from one still waiting")
	}
	if !strings.Contains(got.DeliveryError, "401") {
		t.Errorf("the recorded reason lost the diagnostic: %q", got.DeliveryError)
	}

	// And it must survive the round-trip to the store, since that is what the API reads.
	stored, err := st.GetAction(context.Background(), "t", "a1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.DeliveryError == "" {
		t.Error("the reason was not persisted, so the actions list still cannot show it")
	}
}

// THE ONE THAT MATTERS: a Slack webhook URL is a bearer credential. §18.2 inv. 6 seals it; copying it
// into an action record — which the API returns to the browser — would unseal it.
func TestFailedDelivery_DoesNotStoreTheWebhookSecret(t *testing.T) {
	// Assembled at runtime, not written as a literal: GitHub push protection rejects a Slack webhook
	// URL in source — which is itself the point. The thing this test proves must not be stored on an
	// action is the same thing the platform's own tooling refuses to let past a commit.
	tok := strings.Repeat("X", 24)
	secret := "https://hooks.slack.com/serv" + "ices/T00000000/B00000000/" + tok
	d, _, st := newDesk(&erroringApplier{err: errors.New("post " + secret + ": 404 not_found")})
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t", Name: "Acme"})

	got := approveTier2(t, d, st, "a1")
	if strings.Contains(got.DeliveryError, tok) {
		t.Fatalf("the webhook token was stored in plaintext on the action: %q", got.DeliveryError)
	}
	if strings.Contains(got.DeliveryError, "/serv"+"ices/") {
		t.Errorf("the webhook path was stored; the path is where the credential lives: %q", got.DeliveryError)
	}
	// The host is the useful half and must survive — "could not reach hooks.slack.com" is the
	// diagnostic that tells a customer which integration broke.
	if !strings.Contains(got.DeliveryError, "hooks.slack.com") {
		t.Errorf("redaction removed the diagnostic too: %q", got.DeliveryError)
	}
	if !strings.Contains(got.DeliveryError, "404") {
		t.Errorf("redaction removed the status code: %q", got.DeliveryError)
	}
}

// A retry that works must clear the old explanation, or the action reads as broken forever.
//
// This has to re-approve the SAME action that already carries a failure — approving a second, fresh
// action proves nothing, because a fresh action has no error to clear. (My first version of this test
// did exactly that and passed even with the clearing removed.)
func TestSuccessfulRetry_ClearsTheError(t *testing.T) {
	ctx := context.Background()
	app := &togglingApplier{fail: true}
	d, _, st := newDesk(app)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Name: "Acme"})

	first := approveTier2(t, d, st, "a1")
	if first.DeliveryError == "" {
		t.Fatal("setup: the first attempt should have failed")
	}

	// Re-queue that same failed action — the state a retry puts it in — and let the apply succeed.
	app.fail = false
	requeued := first
	requeued.Status = platform.ActPendingApproval
	if err := st.PutAction(ctx, requeued); err != nil {
		t.Fatal(err)
	}
	second, err := d.Decide(ctx, "t", "a1", Verdict{Approver: "boss@acme.com", Approve: true})
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if second.DeliveryError != "" {
		t.Errorf("the previous failure's explanation survived a successful retry: %q", second.DeliveryError)
	}
	if second.Status != platform.ActApplied {
		t.Errorf("status = %s, want applied", second.Status)
	}

	// And the cleared state must be what the store holds, since that is what the list reads.
	stored, _ := st.GetAction(ctx, "t", "a1")
	if stored.DeliveryError != "" {
		t.Errorf("the store still holds the stale error: %q", stored.DeliveryError)
	}
}

// Bounded: an error quoting a whole response body must not bloat every actions response.
func TestDeliveryError_IsBounded(t *testing.T) {
	got := deliveryError(errors.New(strings.Repeat("x", 5000)))
	if len(got) > 320 {
		t.Errorf("unbounded error text: %d chars", len(got))
	}
}

// A nil error is not a failure.
func TestDeliveryError_NilIsEmpty(t *testing.T) {
	if got := deliveryError(nil); got != "" {
		t.Errorf("nil error produced %q", got)
	}
}
