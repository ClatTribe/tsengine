package platformapi

import (
	"context"
	"net/url"
	"regexp"
	"testing"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// recMailer captures the last email body so the test can pull the reset token out of the link.
type recMailer struct{ body string }

func (m *recMailer) Send(_ context.Context, _, _, body string) error { m.body = body; return nil }
func (m *recMailer) Configured() bool                                { return true }

var tokenRE = regexp.MustCompile(`token=([^&"]+)`)

func TestPasswordReset_FullFlow(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	hash, _ := authn.HashPassword("old-password-123")
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ada@acme.com", Role: platform.RoleOwner, PasswordHash: hash})
	mail := &recMailer{}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Mailer: mail, AppURL: "https://app.acme.io"})

	// forgot → 200 (and the same body whether or not the account exists, so also try a stranger).
	if rec := do(h, "POST", "/v1/auth/forgot", "t1", `{"email":"ada@acme.com"}`); rec.Code != 200 {
		t.Fatalf("forgot → 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "POST", "/v1/auth/forgot", "t1", `{"email":"nobody@nowhere.com"}`); rec.Code != 200 {
		t.Fatalf("forgot for unknown email must still be 200 (no enumeration), got %d", rec.Code)
	}
	m := tokenRE.FindStringSubmatch(mail.body)
	if m == nil {
		t.Fatalf("reset email should contain a token link; body=%q", mail.body)
	}
	token, _ := url.QueryUnescape(m[1])

	// a wrong token is refused.
	if rec := do(h, "POST", "/v1/auth/reset", "t1", `{"email":"ada@acme.com","token":"wrong","new_password":"brand-new-pw-1"}`); rec.Code != 400 {
		t.Fatalf("wrong token → 400, got %d", rec.Code)
	}
	// the real token resets the password.
	if rec := do(h, "POST", "/v1/auth/reset", "t1", `{"email":"ada@acme.com","token":"`+token+`","new_password":"brand-new-pw-1"}`); rec.Code != 200 {
		t.Fatalf("valid reset → 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// the new password now works, the old one doesn't.
	u, _ := st.GetUserByEmail(ctx, "ada@acme.com")
	if !authn.VerifyPassword("brand-new-pw-1", u.PasswordHash) {
		t.Error("new password should verify after reset")
	}
	if authn.VerifyPassword("old-password-123", u.PasswordHash) {
		t.Error("old password must no longer work")
	}
	// the token is single-use: replaying it now fails (it was cleared).
	if rec := do(h, "POST", "/v1/auth/reset", "t1", `{"email":"ada@acme.com","token":"`+token+`","new_password":"another-pw-99"}`); rec.Code != 400 {
		t.Fatalf("reused token → 400, got %d", rec.Code)
	}
}

// A password reset must REVOKE every existing session for that user — a stolen token can't outlive the
// password it was issued under — while leaving other users' sessions untouched.
func TestPasswordReset_RevokesExistingSessions(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	hash, _ := authn.HashPassword("old-password-123")
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ada@acme.com", Role: platform.RoleOwner, PasswordHash: hash})
	_ = st.PutSession(ctx, platform.Session{Token: "victim-live-token", UserID: "u1", TenantID: "t1"})
	// an unrelated user's session must survive the reset.
	_ = st.PutUser(ctx, platform.User{ID: "u2", TenantID: "t1", Email: "bob@acme.com", PasswordHash: hash})
	_ = st.PutSession(ctx, platform.Session{Token: "bystander-token", UserID: "u2", TenantID: "t1"})

	mail := &recMailer{}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Mailer: mail, AppURL: "https://app.acme.io"})

	_ = do(h, "POST", "/v1/auth/forgot", "t1", `{"email":"ada@acme.com"}`)
	m := tokenRE.FindStringSubmatch(mail.body)
	if m == nil {
		t.Fatalf("reset email should contain a token; body=%q", mail.body)
	}
	token, _ := url.QueryUnescape(m[1])
	if rec := do(h, "POST", "/v1/auth/reset", "t1", `{"email":"ada@acme.com","token":"`+token+`","new_password":"brand-new-pw-1"}`); rec.Code != 200 {
		t.Fatalf("valid reset → 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// SECURITY: the pre-reset session must be dead.
	if _, err := st.GetSession(ctx, "victim-live-token"); err == nil {
		t.Fatal("SECURITY: the victim's pre-reset session survived the password reset")
	}
	// the unrelated user's session is untouched.
	if _, err := st.GetSession(ctx, "bystander-token"); err != nil {
		t.Fatalf("an unrelated user's session must survive the reset, got %v", err)
	}
}

func TestPasswordReset_ShortPasswordRejected(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	if rec := do(h, "POST", "/v1/auth/reset", "t1", `{"email":"x@y.com","token":"t","new_password":"short"}`); rec.Code != 400 {
		t.Fatalf("a <8-char password → 400, got %d", rec.Code)
	}
}
