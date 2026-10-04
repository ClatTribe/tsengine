package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type boardMailer struct {
	to, bodies []string
	fail       map[string]bool
	off        bool
}

func (m *boardMailer) Send(_ context.Context, to, _, body string) error {
	if m.fail[to] {
		return context.DeadlineExceeded
	}
	m.to = append(m.to, to)
	m.bodies = append(m.bodies, body)
	return nil
}
func (m *boardMailer) Configured() bool { return !m.off }

func boardTenant(t *testing.T) (*store.Memory, *boardMailer, Deps) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "cto@acme.com", Role: platform.RoleOwner})
	_ = st.PutUser(ctx, platform.User{ID: "u2", TenantID: "t1", Email: "board@acme.com", Role: platform.RoleAuditor})
	m := &boardMailer{}
	return st, m, Deps{Store: st, Mailer: m, AppURL: "https://app.example"}
}

func putDigest(t *testing.T, d Deps, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handlePutBoardDigest(rec, httptest.NewRequest(http.MethodPut, "/v1/settings/board-digest", strings.NewReader(body)), "t1")
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The report lists exploitable exposure, so an address without a seat is REFUSED — not dropped, which
// would leave the owner believing a board member is on the list.
func TestBoardDigest_RecipientsMustHoldASeat(t *testing.T) {
	_, _, d := boardTenant(t)
	code, out := putDigest(t, d, `{"enabled":true,"cadence":"monthly","recipients":["board@acme.com","investor@vc.example"]}`)
	if code != http.StatusBadRequest || out["code"] != "recipient_not_a_seat" {
		t.Fatalf("an external address was accepted: %d %v", code, out)
	}
	if ns, _ := out["not_seats"].([]any); len(ns) != 1 || ns[0] != "investor@vc.example" {
		t.Errorf("the refused address must be named: %v", out["not_seats"])
	}
	if code, out := putDigest(t, d, `{"enabled":true,"cadence":"daily","recipients":["board@acme.com"]}`); code != http.StatusBadRequest || out["code"] != "bad_cadence" {
		t.Errorf("an unknown cadence was accepted: %d %v", code, out)
	}
	if code, _ := putDigest(t, d, `{"enabled":true,"cadence":"weekly","recipients":[" Board@Acme.com ","board@acme.com"]}`); code != http.StatusOK {
		t.Errorf("a seat holder (case/space-insensitive, deduped) was refused: %d", code)
	}
}

// Sent on schedule, once per period, and re-checked against seats at SEND time: a recipient whose seat
// was removed stops receiving the report, and the reason is stored where the owner will see it.
func TestBoardDigest_SendsWhenDueOnlyToCurrentSeats(t *testing.T) {
	ctx := context.Background()
	st, m, d := boardTenant(t)
	if code, _ := putDigest(t, d, `{"enabled":true,"cadence":"weekly","recipients":["cto@acme.com","board@acme.com"]}`); code != http.StatusOK {
		t.Fatal("schedule refused")
	}
	d.SendDueBoardDigest(ctx, "t1")
	if len(m.to) != 2 {
		t.Fatalf("a never-sent schedule is due immediately; sent to %v", m.to)
	}
	if !strings.Contains(m.bodies[0], "Nothing has been scanned yet") || !strings.Contains(m.bodies[0], "https://app.example/board") {
		t.Errorf("the email must carry the report's own headline (unmeasured is not safe) and link: %s", m.bodies[0])
	}
	d.SendDueBoardDigest(ctx, "t1")
	if len(m.to) != 2 {
		t.Fatalf("sent again inside the same week: %v", m.to)
	}

	// A week later, after the board member's seat was removed.
	tn, _ := st.GetTenant(ctx, "t1")
	tn.BoardDigest.LastSentAt = time.Now().UTC().AddDate(0, 0, -8)
	_ = st.PutTenant(ctx, tn)
	// The seat no longer belongs to that address (the store has no delete; a changed address is the same
	// fact from the recipient list's point of view: board@acme.com no longer holds a seat).
	_ = st.PutUser(ctx, platform.User{ID: "u2", TenantID: "t1", Email: "someone-else@acme.com", Role: platform.RoleAuditor})
	d.SendDueBoardDigest(ctx, "t1")
	if len(m.to) != 3 || m.to[2] != "cto@acme.com" {
		t.Fatalf("a removed seat must stop receiving it: %v", m.to)
	}
	tn, _ = st.GetTenant(ctx, "t1")
	if !strings.Contains(tn.BoardDigest.LastError, "board@acme.com") {
		t.Errorf("the skipped recipient must be named in the stored outcome: %q", tn.BoardDigest.LastError)
	}
}

// A send where nothing was delivered does not advance the schedule — it retries next pass — and the
// failure is stored rather than swallowed.
func TestBoardDigest_FailedDeliveryDoesNotCountAsSent(t *testing.T) {
	ctx := context.Background()
	st, m, d := boardTenant(t)
	putDigest(t, d, `{"enabled":true,"cadence":"monthly","recipients":["cto@acme.com"]}`)
	m.fail = map[string]bool{"cto@acme.com": true}
	d.SendDueBoardDigest(ctx, "t1")
	tn, _ := st.GetTenant(ctx, "t1")
	if !tn.BoardDigest.LastSentAt.IsZero() || tn.BoardDigest.LastError == "" || tn.BoardDigest.LastAttemptAt.IsZero() {
		t.Fatalf("a failed delivery was recorded as sent or not recorded: %+v", tn.BoardDigest)
	}
	m.fail = nil
	d.SendDueBoardDigest(ctx, "t1")
	if len(m.to) != 1 {
		t.Errorf("the next pass must retry: %v", m.to)
	}
}

// No mail relay: nothing is sent, and Settings SAYS nothing will be — a saved schedule must not read as a
// working one.
func TestBoardDigest_NoRelayIsSaidNotSilent(t *testing.T) {
	_, m, d := boardTenant(t)
	m.off = true
	code, out := putDigest(t, d, `{"enabled":true,"cadence":"weekly","recipients":["cto@acme.com"]}`)
	if code != http.StatusOK || out["delivery_configured"] != false || out["delivery_note"] == nil {
		t.Fatalf("no relay must be stated: %d %v", code, out)
	}
	d.SendDueBoardDigest(context.Background(), "t1")
	if len(m.to) != 0 {
		t.Error("sent with no relay configured")
	}
}

// The schedule is an owner decision: the settings prefix gate refuses a member.
func TestBoardDigest_IsOwnerOnly(t *testing.T) {
	for _, r := range [][2]string{{"PUT", "/v1/settings/board-digest"}, {"POST", "/v1/settings/board-digest/send"}} {
		if !ownerOnlyRoute(r[0], r[1]) {
			t.Errorf("%s %s must be owner-only", r[0], r[1])
		}
	}
}
