package platformapi

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

// The public "talk to sales" / book-a-demo lead capture. A prospect submits their details from
// the marketing site (no account); the lead is validated, rate-limited, and recorded. Today it
// lands in the structured log (greppable + alertable via the slog/metrics stack); routing it to
// a CRM or sales inbox is the cred-gated next step — never claimed as done here.

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
	slog.Info("sales lead",
		"name", name, "email", email,
		"company", strings.TrimSpace(body.Company),
		"source", strings.TrimSpace(body.Source),
		"message", truncate(strings.TrimSpace(body.Message), 500),
	)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
