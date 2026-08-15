package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"
)

// The public "talk to sales" / book-a-demo lead capture. A prospect submits their details from
// the marketing site (no account); the lead is validated, rate-limited, recorded, and — when the
// operator has configured a destination — emailed to the sales inbox.
//
// Delivery used to be the missing half. The lead landed in the structured log and went no further,
// while the form told the person "we'll only use your details to get in touch". Every inbound
// motion terminates at this handler — the /scan lead magnet, the pricing CTAs, outbound replies —
// so a lead that stopped at a log line was a lead nobody followed up unless someone happened to be
// grepping production logs.
//
// It is gated the way the rest of the operator config is: TSENGINE_SALES_EMAIL sets the
// destination and Deps.Mailer comes from email.FromEnv (SMTP_*). With either unset the behaviour
// is exactly what it was — log only — so a deployment that has not configured mail breaks nothing.
// Routing to a CRM is still the next step and is not claimed here.

type leadRequest struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Message string `json:"message"`
	Source  string `json:"source"` // where the form was submitted from (pricing, demo-page, …)
}

// leadLimiter bounds the public endpoint (a contact form is a spam target): max 5 per IP/minute.
var leadLimiter = &assessLimiter{hit: map[string][]time.Time{}, max: 5}

// handleLead (PUBLIC — no bearer) records a sales/demo lead.
func (d Deps) handleLead(w http.ResponseWriter, r *http.Request) {
	var body leadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name := strings.TrimSpace(body.Name)
	email := strings.TrimSpace(body.Email)
	if name == "" || email == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name and work email are required"))
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("enter a valid work email"))
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !leadLimiter.allow(ip, time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many requests — try again shortly"))
		return
	}
	company, source := strings.TrimSpace(body.Company), strings.TrimSpace(body.Source)
	message := truncate(strings.TrimSpace(body.Message), 500)
	// The log line stays the durable record whether or not mail is configured — it is what makes a
	// failed or unconfigured delivery recoverable rather than lost.
	slog.Info("sales lead",
		"name", name, "email", email,
		"company", company,
		"source", source,
		"message", message,
	)
	d.notifySalesLead(r.Context(), name, email, company, source, message)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// notifySalesLead emails the lead to the operator's sales inbox. Best-effort by design: the person
// has already submitted, and our SMTP being down is not their problem — a failure is logged and the
// caller still gets {"ok":true}. Silent no-op when unconfigured (no TSENGINE_SALES_EMAIL, or no
// Mailer because SMTP_* is unset), which keeps existing deployments behaving exactly as before.
//
// The request context is detached with WithoutCancel: the visitor's browser disconnecting the
// moment it has its 200 must not cancel the notification that this whole funnel exists to produce.
// Bounded at 10s so a hung SMTP server cannot hold the handler open.
func (d Deps) notifySalesLead(ctx context.Context, name, email, company, source, message string) {
	to := strings.TrimSpace(os.Getenv("TSENGINE_SALES_EMAIL"))
	// Mailer implementations are nil-safe by contract, but Deps.Mailer is an interface field that may
	// itself be nil, so that is still guarded. Configured() is the honest check for whether real
	// delivery is wired — without it a Noop mailer would silently "succeed" and we would believe the
	// lead had been delivered when SMTP was never set up.
	if to == "" || d.Mailer == nil || !d.Mailer.Configured() {
		return
	}
	who := company
	if who == "" {
		who = name
	}
	subject := fmt.Sprintf("New lead: %s", who)
	if source != "" {
		subject += fmt.Sprintf(" (%s)", source)
	}
	// Every field here is attacker-controlled — this is a public, unauthenticated form — so each one
	// is escaped before it goes into an HTML mail body.
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString("<p><strong>New sales lead</strong></p><ul>")
	fmt.Fprintf(&b, "<li>Name: %s</li>", esc(name))
	fmt.Fprintf(&b, "<li>Email: %s</li>", esc(email))
	if company != "" {
		fmt.Fprintf(&b, "<li>Company: %s</li>", esc(company))
	}
	if source != "" {
		fmt.Fprintf(&b, "<li>Source: %s</li>", esc(source))
	}
	b.WriteString("</ul>")
	if message != "" {
		fmt.Fprintf(&b, "<p><strong>Message</strong></p><p>%s</p>", esc(message))
	}

	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := d.Mailer.Send(sendCtx, to, subject, b.String()); err != nil {
		slog.Error("sales lead: delivery failed (the lead is still in the log line above)",
			"error", err, "email", email, "source", source)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
