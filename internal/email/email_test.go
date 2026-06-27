package email

import (
	"context"
	"testing"
)

func TestFromEnv_NoHostIsNoop(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	m := FromEnv()
	if m.Configured() {
		t.Error("no SMTP_HOST → mailer must report not configured")
	}
	if err := m.Send(context.Background(), "a@b.com", "hi", "<p>x</p>"); err != nil {
		t.Errorf("noop Send must succeed silently, got %v", err)
	}
}

func TestFromEnv_BuildsSMTP(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("SMTP_FROM", "")
	m := FromEnv()
	if !m.Configured() {
		t.Fatal("SMTP_HOST set → configured")
	}
	s := m.(*SMTP)
	if s.Port != "587" {
		t.Errorf("default port should be 587, got %s", s.Port)
	}
	if s.From == "" {
		t.Error("From should default")
	}
}

func TestSMTP_RejectsBadRecipient(t *testing.T) {
	s := &SMTP{Host: "smtp.example.com"}
	if err := s.Send(context.Background(), "not-an-email", "s", "b"); err == nil {
		t.Error("a recipient with no @ should error before dialing")
	}
}

func TestSenderAddr(t *testing.T) {
	if got := senderAddr("TensorShield <noreply@tensorshield.io>"); got != "noreply@tensorshield.io" {
		t.Errorf("senderAddr extracted %q", got)
	}
	if got := senderAddr("plain@x.io"); got != "plain@x.io" {
		t.Errorf("bare address: %q", got)
	}
}
