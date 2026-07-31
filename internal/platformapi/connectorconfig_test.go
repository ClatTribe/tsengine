package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func connectURL(h http.Handler) *httptest.ResponseRecorder {
	return do(h, http.MethodGet, "/v1/connect/github", "t1", "")
}

func handlerWithGitHub(id, secret string) http.Handler {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	return NewHandler(Deps{
		Store:      st,
		Connectors: connector.NewRegistry(connector.NewGitHub(id, secret)),
		Token:      "platform-tok",
		PublicURL:  "https://app.example.com",
	})
}

// An unconfigured OAuth connector used to build ".../authorize?client_id=&..." and dump the
// customer on the provider's error page, with nothing logged server-side to explain it. It must
// fail here instead, with something an operator can act on.
func TestConnectURL_UnconfiguredConnectorFailsClearly(t *testing.T) {
	h := handlerWithGitHub("", "") // exactly what an unset GITHUB_CLIENT_ID produces
	rec := connectURL(h)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 for an unconfigured connector, got %d: %s", rec.Code, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "connector_not_configured" {
		t.Errorf("want a machine-readable reason, got %v", body)
	}
	if _, leaked := body["authorize_url"]; leaked {
		t.Errorf("an unconfigured connector must not return an authorize_url: %v", body)
	}
}

func TestConnectURL_ConfiguredConnectorStillWorks(t *testing.T) {
	h := handlerWithGitHub("id-123", "secret-abc")
	rec := connectURL(h)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["authorize_url"] == "" {
		t.Fatalf("expected an authorize_url, got %v", body)
	}
}

func TestRegistry_ConfiguredKindsFiltersUnusable(t *testing.T) {
	reg := connector.NewRegistry(
		connector.NewGitHub("id", "secret"), // usable
		connector.NewGitLab("", ""),         // not configured
	)
	if got := len(reg.Kinds()); got != 2 {
		t.Fatalf("Kinds() should list everything registered, got %d", got)
	}
	cfg := reg.ConfiguredKinds()
	if len(cfg) != 1 || cfg[0] != platform.ConnGitHub {
		t.Fatalf("ConfiguredKinds() should list only usable connectors, got %v", cfg)
	}
}

// --- invites ---------------------------------------------------------------

type capturingMailer struct {
	to, subject, body string
}

func (m *capturingMailer) Send(_ context.Context, to, subject, body string) error {
	m.to, m.subject, m.body = to, subject, body
	return nil
}
func (m *capturingMailer) Configured() bool { return true }

// With SMTP configured the credential goes to the INVITEE and is NOT echoed back, so it never
// transits the owner's browser or the API logs.
func TestInvite_EmailsCredentialAndDoesNotReturnIt(t *testing.T) {
	st := store.NewMemory()
	mailer := &capturingMailer{}
	h := NewHandler(Deps{Store: st, Token: "platform-tok", Mailer: mailer, PublicURL: "https://app.example.com"})

	owner := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Initech","email":"boss@initech.com","password":"ownerpass1"}`)
	var o struct{ Token string }
	_ = json.Unmarshal(owner.Body.Bytes(), &o)

	inv := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"dev@initech.com","name":"Dev"}`)
	if inv.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", inv.Code, inv.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(inv.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["emailed"] != true {
		t.Fatalf("expected emailed=true, got %v", body)
	}
	if _, leaked := body["temp_password"]; leaked {
		t.Error("the credential must not be returned when it was emailed")
	}
	if mailer.to != "dev@initech.com" {
		t.Errorf("invite went to %q, want dev@initech.com", mailer.to)
	}
	if mailer.body == "" || mailer.subject == "" {
		t.Error("invite email had no subject/body")
	}
}

// With no SMTP the previous behaviour is preserved — the owner gets the password to relay — but
// the response now says so rather than being indistinguishable from a delivered invite.
func TestInvite_NoMailerReturnsCredentialForRelay(t *testing.T) {
	h, _ := setup(t) // setup() wires no Mailer

	owner := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Initech","email":"boss2@initech.com","password":"ownerpass1"}`)
	var o struct{ Token string }
	_ = json.Unmarshal(owner.Body.Bytes(), &o)

	inv := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"dev2@initech.com"}`)
	if inv.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", inv.Code, inv.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(inv.Body.Bytes(), &body)
	if body["emailed"] != false {
		t.Errorf("expected emailed=false, got %v", body)
	}
	if s, _ := body["temp_password"].(string); len(s) < 8 {
		t.Error("with no mailer the owner needs the credential to relay")
	}
}
