package webagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EvidenceBundle is the tamper-evident VAPT deliverable for one engagement: each
// recorded finding bundled with the exact proving request/response turns that
// grounded it, plus an ed25519 attestation over the canonical JSON. An auditor (or
// webappsec) can re-read the PoC and verify the bundle was not altered after
// signing. Mirrors the L1 dashboard attestation (internal/dashboard) but scoped to
// an offensive engagement rather than a scan.
type EvidenceBundle struct {
	Target      string            `json:"target"`
	Engine      string            `json:"engine"`
	GeneratedAt time.Time         `json:"generated_at"`
	Summary     string            `json:"summary,omitempty"`
	Findings    []EvidenceFinding `json:"findings"`
	Attestation *EvidenceAttest   `json:"attestation,omitempty"`
}

// EvidenceFinding is one finding + the proving turns it cites. The proving turns
// carry the request (method/url/payload) AND the response (status/indicators/
// snippet) — the reproducible PoC.
type EvidenceFinding struct {
	Finding
	ProvingTurns []Turn `json:"proving_turns"`
}

// EvidenceAttest is the signature block (SHA-256 of canonical JSON + ed25519).
type EvidenceAttest struct {
	SHA256    string    `json:"sha256"`
	SignedAt  time.Time `json:"signed_at"`
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
}

// BuildEvidence assembles the bundle from a finished report + the engagement
// context (for resolving cited turn IDs to their full request/response turns).
func BuildEvidence(rep *Report, cc *Context, engine string) *EvidenceBundle {
	b := &EvidenceBundle{
		Target: rep.Target, Engine: engine, Summary: rep.Summary,
		Findings: make([]EvidenceFinding, 0, len(rep.Findings)),
	}
	for _, f := range rep.Findings {
		ef := EvidenceFinding{Finding: f}
		for _, tid := range f.Evidence {
			if t, ok := cc.turn(tid); ok {
				ef.ProvingTurns = append(ef.ProvingTurns, t)
			}
		}
		b.Findings = append(b.Findings, ef)
	}
	return b
}

// canonEvidence produces the canonical bytes signed/verified: the bundle with its
// Attestation block stripped. The bundle contains NO maps (only structs + slices),
// so encoding/json emits fields in declaration order — deterministic without a
// bespoke canonicaliser.
func canonEvidence(b *EvidenceBundle) ([]byte, error) {
	clone := *b
	clone.Attestation = nil
	return json.Marshal(clone)
}

// SignEvidence computes the SHA-256 over the canonical bundle and signs it,
// populating the Attestation block. now is a clock injection point (tests pin it).
func SignEvidence(b *EvidenceBundle, signer string, priv ed25519.PrivateKey, now time.Time) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("evidence: invalid private key length %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if signer == "" {
		return errors.New("evidence: empty signer")
	}
	if b.GeneratedAt.IsZero() {
		b.GeneratedAt = now.UTC()
	}
	canon, err := canonEvidence(b)
	if err != nil {
		return fmt.Errorf("evidence: canonical: %w", err)
	}
	sum := sha256.Sum256(canon)
	sig := ed25519.Sign(priv, sum[:])
	b.Attestation = &EvidenceAttest{
		SHA256:    hex.EncodeToString(sum[:]),
		SignedAt:  now.UTC(),
		Signer:    signer,
		Signature: hex.EncodeToString(sig),
	}
	return nil
}

// VerifyEvidence checks the bundle's attestation against pub. Returns nil iff the
// bundle is intact and the signature is valid.
func VerifyEvidence(b *EvidenceBundle, pub ed25519.PublicKey) error {
	if b.Attestation == nil {
		return errors.New("evidence: missing attestation")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("evidence: invalid public key length %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	canon, err := canonEvidence(b)
	if err != nil {
		return fmt.Errorf("evidence: canonical: %w", err)
	}
	sum := sha256.Sum256(canon)
	if want := hex.EncodeToString(sum[:]); b.Attestation.SHA256 != want {
		return fmt.Errorf("evidence: hash mismatch (got %s, want %s) — bundle was altered after signing", b.Attestation.SHA256, want)
	}
	sig, err := hex.DecodeString(b.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("evidence: signature decode: %w", err)
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return errors.New("evidence: signature verification failed")
	}
	return nil
}

// ExportEvidence writes the bundle as indented JSON to path (creating parent dirs).
func ExportEvidence(path string, b *EvidenceBundle) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadEvidence reads a bundle from path.
func LoadEvidence(path string) (*EvidenceBundle, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, err
	}
	var b EvidenceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("evidence: decode: %w", err)
	}
	return &b, nil
}
