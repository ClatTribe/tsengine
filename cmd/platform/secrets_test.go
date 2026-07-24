package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHydrateFileSecrets(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(keyFile, []byte("  base64-key-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// KEY unset + KEY_FILE set → loaded (trimmed).
	t.Setenv("TSENGINE_SECRET_KEY", "")
	os.Unsetenv("TSENGINE_SECRET_KEY")
	t.Setenv("TSENGINE_SECRET_KEY_FILE", keyFile)
	hydrateFileSecrets()
	if got := os.Getenv("TSENGINE_SECRET_KEY"); got != "base64-key-value" {
		t.Errorf("file secret not hydrated/trimmed: %q", got)
	}

	// An inline KEY wins over KEY_FILE.
	t.Setenv("TSENGINE_PLATFORM_TOKEN", "inline-token")
	t.Setenv("TSENGINE_PLATFORM_TOKEN_FILE", keyFile)
	hydrateFileSecrets()
	if got := os.Getenv("TSENGINE_PLATFORM_TOKEN"); got != "inline-token" {
		t.Errorf("inline value must win over *_FILE: %q", got)
	}

	// A missing KEY_FILE is non-fatal and leaves KEY unset.
	t.Setenv("TSENGINE_WEBHOOK_SECRET", "")
	os.Unsetenv("TSENGINE_WEBHOOK_SECRET")
	t.Setenv("TSENGINE_WEBHOOK_SECRET_FILE", filepath.Join(dir, "nope"))
	hydrateFileSecrets() // must not panic / fatal
	if got := os.Getenv("TSENGINE_WEBHOOK_SECRET"); got != "" {
		t.Errorf("unreadable *_FILE should leave the key unset, got %q", got)
	}
}

func TestRequireSealedSecrets_FailsClosed(t *testing.T) {
	// No opt-in → refuse to start (fail closed: plaintext creds are never a silent default).
	if err := requireSealedSecrets(""); err == nil {
		t.Error("missing sealing key without the dev opt-in must be fatal (fail closed)")
	}
	// Explicit dev opt-in → allowed.
	if err := requireSealedSecrets("1"); err != nil {
		t.Errorf("TSENGINE_ALLOW_UNSEALED_SECRETS=1 should permit plaintext for dev, got %v", err)
	}
}
