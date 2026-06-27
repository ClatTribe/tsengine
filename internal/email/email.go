// Package email is the transactional-email seam: a small Mailer interface with an SMTP
// implementation (net/smtp, STARTTLS) and a no-op fallback. It carries password-reset links,
// member invites, and alerts. The provider is operator-configured via env (the credential-gated
// half); with nothing configured the platform degrades to the in-UI temp-password flow.
package email

import (
	"context"
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// Mailer sends one transactional message. Implementations must be safe to call on a nil/zero
// value (a no-op), so callers never need to nil-check.
type Mailer interface {
	Send(ctx context.Context, to, subject, htmlBody string) error
	// Configured reports whether real delivery is wired (so callers can choose to also surface
	// an out-of-band fallback, e.g. show an invite's temp password in the UI when email is off).
	Configured() bool
}

// SMTP delivers via an SMTP relay using PLAIN auth over STARTTLS (port 587 style). A zero SMTP
// (no host) is a no-op, so it's safe as a default.
type SMTP struct {
	Host string
	Port string
	User string
	Pass string
	From string // e.g. "TensorShield <noreply@tensorshield.io>"
}

// FromEnv builds an SMTP mailer from SMTP_HOST / SMTP_PORT / SMTP_USERNAME / SMTP_PASSWORD /
// SMTP_FROM. Missing SMTP_HOST → a no-op mailer (delivery disabled, never an error).
func FromEnv() Mailer {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		return Noop{}
	}
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if port == "" {
		port = "587"
	}
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	if from == "" {
		from = "TensorShield <noreply@tensorshield.io>"
	}
	return &SMTP{
		Host: host, Port: port,
		User: os.Getenv("SMTP_USERNAME"), Pass: os.Getenv("SMTP_PASSWORD"),
		From: from,
	}
}

func (s *SMTP) Configured() bool { return s != nil && strings.TrimSpace(s.Host) != "" }

func (s *SMTP) Send(ctx context.Context, to, subject, htmlBody string) error {
	if !s.Configured() {
		return nil // no-op when unconfigured
	}
	to = strings.TrimSpace(to)
	if to == "" || !strings.Contains(to, "@") {
		return fmt.Errorf("email: invalid recipient %q", to)
	}
	// RFC 5322 message with an HTML body. \r\n line endings per SMTP.
	msg := strings.NewReplacer("\n", "\r\n").Replace(strings.Join([]string{
		"From: " + s.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"",
		htmlBody,
	}, "\n"))

	addr := s.Host + ":" + s.Port
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Pass, s.Host)
	}
	// smtp.SendMail negotiates STARTTLS when the server advertises it (the common 587 path).
	if err := smtp.SendMail(addr, auth, senderAddr(s.From), []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("email: send to %s: %w", to, err)
	}
	return nil
}

// senderAddr extracts the bare address from a "Name <addr>" From header for the SMTP envelope.
func senderAddr(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j > 0 {
			return strings.TrimSpace(from[i+1 : i+j])
		}
	}
	return strings.TrimSpace(from)
}

// Noop is the disabled mailer: every Send succeeds silently. Used when no SMTP is configured.
type Noop struct{}

func (Noop) Send(context.Context, string, string, string) error { return nil }
func (Noop) Configured() bool                                   { return false }
