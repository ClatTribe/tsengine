package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// D5 acceptance: sign → tamper → verify fails; verify → clean passes.
func TestSignTraceFile_VerifyRoundtripAndTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	recs := []TraceRecord{
		{Stage: "detection", Detail: "3 anchors fired", Disposition: "ok"},
		{Stage: "sweep", Detail: "planned=12 ran=12 candidates=2 refused=3", Model: "hy3-free",
			TokensIn: 4500, TokensOut: 350, Disposition: "ok"},
	}
	if err := SignTraceFile(path, recs, "qa-signer", priv, time.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyTraceFile(path, pub); err != nil {
		t.Fatalf("a signed trace must verify: %v", err)
	}

	// Tamper with a record AFTER signing — the chain (not just the signature) must catch it.
	blob, _ := os.ReadFile(path)
	tampered := []byte(replaceOnce(string(blob), `"detail": "planned=12 ran=12 candidates=2 refused=3"`, `"detail": "planned=12 ran=12 candidates=999 refused=0"`))
	if string(tampered) == string(blob) {
		t.Fatal("tamper replacement did not apply")
	}
	tamperedPath := filepath.Join(dir, "trace-tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTraceFile(tamperedPath, pub); err == nil {
		t.Fatal("a tampered record must FAIL verification — that is the entire point of the artifact")
	}
}

func TestSignTraceFile_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	recs := []TraceRecord{{Stage: "detection", Disposition: "ok"}}
	if err := SignTraceFile(path, recs, "s", priv, time.Now()); err != nil {
		t.Fatal(err)
	}
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyTraceFile(path, wrongPub); err == nil {
		t.Error("verification against a different key must fail")
	}
}

func replaceOnce(s, old, new string) string {
	idx := indexOf(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
