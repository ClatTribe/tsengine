package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// revokeFailStore is a Store whose session wipe fails. Everything else behaves normally, so the
// password change itself still succeeds — which is the situation under test.
type revokeFailStore struct {
	store.Store
}

func (revokeFailStore) DeleteSessionsForUser(context.Context, string) error {
	return fmt.Errorf("simulated store failure")
}

// A password change whose session revocation FAILED must say so.
//
// Most people change a password because they believe the old one is compromised, and evicting any
// stolen token is the thing they came to do. The handler swallowed that error and answered
// {"ok":true} — telling exactly that person it worked while an attacker's session stayed valid.
//
// The change itself must still succeed: a user who cannot change their password at all is worse off
// than one whose old sessions linger. So this is reported, not turned into an error.
func TestAuth_PasswordChangeReportsFailedSessionRevocation(t *testing.T) {
	st := revokeFailStore{Store: store.NewMemory()}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	signup := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Acme","email":"a@acme.com","password":"origpass1"}`)
	if signup.Code != http.StatusOK && signup.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", signup.Code, signup.Body.String())
	}
	var s struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(signup.Body.Bytes(), &s)

	res := postJSON(h, "/v1/auth/password", s.Token, `{"current_password":"origpass1","new_password":"brandnewpass1"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("the password change must still succeed: %d %s", res.Code, res.Body.String())
	}
	var body struct {
		OK              bool   `json:"ok"`
		SessionsRevoked *bool  `json:"sessions_revoked"`
		Detail          string `json:"detail"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK {
		t.Error("the password change succeeded and the response should say so")
	}
	if body.SessionsRevoked == nil || *body.SessionsRevoked {
		t.Fatalf("a failed revocation was reported as success: %s", res.Body.String())
	}
	if body.Detail == "" {
		t.Error("the reader needs to be told what did not happen, not just given a false flag")
	}

	// And the new password really is in effect — the report is about the sessions, not the change.
	login := postJSON(h, "/v1/auth/login", "", `{"email":"a@acme.com","password":"brandnewpass1"}`)
	if login.Code != http.StatusOK {
		t.Errorf("the new password should work: %d %s", login.Code, login.Body.String())
	}
}

// The healthy path still reports a plain success with the revocation confirmed, so the field above
// is a real signal rather than one that is always false.
func TestAuth_PasswordChangeConfirmsRevocationOnTheHappyPath(t *testing.T) {
	h, _ := setup(t)
	signup := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Acme2","email":"b@acme.com","password":"origpass1"}`)
	var s struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(signup.Body.Bytes(), &s)

	res := postJSON(h, "/v1/auth/password", s.Token, `{"current_password":"origpass1","new_password":"brandnewpass1"}`)
	var body struct {
		SessionsRevoked bool `json:"sessions_revoked"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &body)
	if !body.SessionsRevoked {
		t.Errorf("a successful revocation should be confirmed: %s", res.Body.String())
	}
	_ = platform.Session{}
}
