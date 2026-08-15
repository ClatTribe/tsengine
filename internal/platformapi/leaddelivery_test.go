package platformapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// captureMailer records what would have been sent, so these tests exercise the real handler path
// (handleLead → notifySalesLead → Mailer.Send) rather than re-implementing the delivery logic.
type captureMailer struct {
	sent         int
	to           string
	subject      string
	body         string
	err          error
	unconfigured bool // mimics a Noop / SMTP-less mailer
}

func (m *captureMailer) Send(_ context.Context, to, subject, htmlBody string) error {
	m.sent++
	m.to, m.subject, m.body = to, subject, htmlBody
	return m.err
}

func (m *captureMailer) Configured() bool { return !m.unconfigured }

// leadTestIP hands out a distinct source address per call. leadLimiter is package-level state
// allowing only 5/min per IP, so a shared address makes the 6th call in the file fail with 429 on
// whatever test happens to run last rather than on anything it asserts.
var leadTestIP atomic.Int64

func postLeadTo(d Deps, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/lead", strings.NewReader(body))
	r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", leadTestIP.Add(1)%250, 1, 1)
	w := httptest.NewRecorder()
	d.handleLead(w, r)
	return w
}

// TestLeadDeliveredToSalesInbox is the regression guard for the gap this closed: a lead used to be
// logged and go no further, so every inbound motion terminated at a log line.
func TestLeadDeliveredToSalesInbox(t *testing.T) {
	m := &captureMailer{}
	t.Setenv("TSENGINE_SALES_EMAIL", "sales@tensorshield.example")

	w := postLeadTo(Deps{Mailer: m}, `{"name":"Ada","email":"ada@acme.com","company":"Acme","source":"pricing:growth","message":"Review blocking a deal"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("lead → %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if m.sent != 1 {
		t.Fatalf("mailer sent %d times, want 1 — the lead never reached the sales inbox", m.sent)
	}
	if m.to != "sales@tensorshield.example" {
		t.Errorf("to = %q, want the configured sales address", m.to)
	}
	// The source carries which pricing tier was clicked — the whole point of routing it through.
	if !strings.Contains(m.subject, "Acme") || !strings.Contains(m.subject, "pricing:growth") {
		t.Errorf("subject = %q, want it to name the company and the source", m.subject)
	}
	for _, want := range []string{"ada@acme.com", "Acme", "pricing:growth", "Review blocking a deal"} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body missing %q:\n%s", want, m.body)
		}
	}
}

// TestLeadDeliveryUnconfiguredIsNoop pins the honest gate: with no destination (or no Mailer) the
// endpoint behaves exactly as it did before, so an existing deployment breaks nothing by upgrading.
func TestLeadDeliveryUnconfiguredIsNoop(t *testing.T) {
	m := &captureMailer{}
	t.Setenv("TSENGINE_SALES_EMAIL", "")

	if w := postLeadTo(Deps{Mailer: m}, `{"name":"Ada","email":"ada@acme.com"}`); w.Code != http.StatusOK {
		t.Fatalf("lead → %d, want 200", w.Code)
	}
	if m.sent != 0 {
		t.Errorf("sent %d times with no TSENGINE_SALES_EMAIL, want 0", m.sent)
	}

	// Configured destination but no Mailer at all (nil interface) must be a no-op, not a panic.
	t.Setenv("TSENGINE_SALES_EMAIL", "sales@tensorshield.example")
	if w := postLeadTo(Deps{}, `{"name":"Ada","email":"ada@acme.com"}`); w.Code != http.StatusOK {
		t.Errorf("nil Mailer → %d, want 200", w.Code)
	}

	// A present-but-unconfigured mailer (the Noop the platform installs when SMTP_* is unset) must
	// not be treated as delivery — otherwise we would believe leads were being sent when they weren't.
	noop := &captureMailer{unconfigured: true}
	if w := postLeadTo(Deps{Mailer: noop}, `{"name":"Ada","email":"ada@acme.com"}`); w.Code != http.StatusOK {
		t.Errorf("unconfigured Mailer → %d, want 200", w.Code)
	}
	if noop.sent != 0 {
		t.Errorf("sent %d times through an unconfigured mailer, want 0", noop.sent)
	}
}

// TestLeadDeliveryFailureStillSucceeds — the visitor already submitted; our SMTP being down is not
// their problem, and the log line remains the recoverable record.
func TestLeadDeliveryFailureStillSucceeds(t *testing.T) {
	m := &captureMailer{err: context.DeadlineExceeded}
	t.Setenv("TSENGINE_SALES_EMAIL", "sales@tensorshield.example")

	if w := postLeadTo(Deps{Mailer: m}, `{"name":"Ada","email":"ada@acme.com"}`); w.Code != http.StatusOK {
		t.Errorf("send failure → %d, want 200 (delivery is best-effort)", w.Code)
	}
}

// TestLeadDeliveryEscapesHTML — /v1/lead is public and unauthenticated, so every field is
// attacker-controlled and must not reach an HTML mail body unescaped.
func TestLeadDeliveryEscapesHTML(t *testing.T) {
	m := &captureMailer{}
	t.Setenv("TSENGINE_SALES_EMAIL", "sales@tensorshield.example")

	postLeadTo(Deps{Mailer: m}, `{"name":"<script>alert(1)</script>","email":"ada@acme.com","message":"<img src=x onerror=alert(1)>"}`)
	if strings.Contains(m.body, "<script>") || strings.Contains(m.body, "<img src=x") {
		t.Errorf("unescaped attacker-controlled markup reached the mail body:\n%s", m.body)
	}
	if !strings.Contains(m.body, "&lt;script&gt;") {
		t.Errorf("expected the name to be HTML-escaped, got:\n%s", m.body)
	}
}
