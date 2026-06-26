// Package grc is the compliance system-of-record (docs/autonomous-team.md §3.6) — the
// lock-in layer. It turns the engine's per-finding control mapping (the compliance.map
// L1.5 hook, surfaced on types.Finding.Compliance) into a continuously-updated,
// per-tenant, per-framework control-state registry, and exports a signed evidence pack
// an auditor/insurer consumes.
//
// Grounding holds: a control is only ever marked "gap" because a real finding cites it;
// the GRC layer asserts nothing the engine did not first prove (the anti-theater guard).
package grc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Frameworks the GRC layer tracks (keys match the EvidencePack + Posture API).
const (
	FrameworkSOC2       = "soc2"
	FrameworkISO27001   = "iso27001"
	FrameworkPCI        = "pci"
	FrameworkHIPAA      = "hipaa"
	FrameworkCISv8      = "cis_v8"
	FrameworkNISTCSF    = "nist_csf"
	FrameworkGDPR       = "gdpr"
	FrameworkISO27701   = "iso27701"
	FrameworkNIST80053  = "nist_800_53"
	FrameworkNIST800171 = "nist_800_171"
	FrameworkCCPA       = "ccpa"
	FrameworkSOX        = "sox"
	FrameworkFedRAMP    = "fedramp"
	FrameworkDPDP       = "dpdp"
	FrameworkCMMC       = "cmmc"
	FrameworkISO42001   = "iso42001"
	FrameworkNISTAIRMF  = "nist_ai_rmf"
)

// Frameworks is the ordered set of frameworks the GRC layer tracks — the single source
// of truth the API/console iterate so a new framework surfaces everywhere at once.
var Frameworks = []string{
	FrameworkSOC2, FrameworkISO27001, FrameworkPCI, FrameworkHIPAA, FrameworkCISv8,
	FrameworkNISTCSF, FrameworkGDPR, FrameworkISO27701, FrameworkNIST80053,
	FrameworkNIST800171, FrameworkCCPA, FrameworkSOX, FrameworkFedRAMP, FrameworkDPDP,
	FrameworkCMMC, FrameworkISO42001, FrameworkNISTAIRMF,
}

// IsFramework reports whether key is one of the tracked frameworks. Callers (the report API)
// validate against this so an unknown framework is a clean 404, never a fabricated empty report
// titled with the bogus key (grounding §10 — we don't render a "compliance report" for a
// framework that doesn't exist).
func IsFramework(key string) bool {
	for _, f := range Frameworks {
		if f == key {
			return true
		}
	}
	return false
}

// GRC maintains the control-state registry over the store.
type GRC struct {
	Store store.Store
	Now   func() time.Time
	// ControlUniverse returns the controls our crosswalk CAN assess for a framework (the tooling-
	// addressable subset). Injected (cmd/platform wires hooks.ControlsFor) so grc stays decoupled +
	// testable. nil → coverage degrades to "unavailable" rather than over-claiming compliance.
	ControlUniverse func(framework string) []string
}

func (g *GRC) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

// Apply folds one finding into the tenant's control state: every control the finding's
// compliance annotation cites is marked a gap, with the finding as evidence. A finding
// with no compliance mapping is a no-op (nothing to assert).
func (g *GRC) Apply(ctx context.Context, tenantID string, f types.Finding) error {
	if f.Compliance == nil {
		return nil
	}
	for framework, controls := range frameworkControls(f.Compliance) {
		for _, ctrl := range controls {
			cs := platform.ControlState{
				TenantID: tenantID, Framework: framework, ControlID: ctrl,
				State: platform.ControlGap, EvidenceRefs: []string{f.ID}, UpdatedAt: g.now(),
			}
			if err := g.Store.UpsertControlState(ctx, cs); err != nil {
				return err
			}
		}
	}
	return nil
}

// Posture returns the tenant's known control state for a framework (deterministic order).
func (g *GRC) Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error) {
	cs, err := g.Store.Posture(ctx, tenantID, framework)
	if err != nil {
		return nil, err
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ControlID < cs[j].ControlID })
	return cs, nil
}

// EvidencePack is the auditor/insurer-consumable, signed compliance artifact.
type EvidencePack struct {
	TenantID    string                  `json:"tenant_id"`
	Framework   string                  `json:"framework"`
	GeneratedAt time.Time               `json:"generated_at"`
	Controls    []platform.ControlState `json:"controls"`
	GapCount    int                     `json:"gap_count"`
	Attestation *Attestation            `json:"attestation,omitempty"`
}

// Attestation signs the pack (SHA-256 of canonical JSON + ed25519), mirroring the
// ledger/evidence scheme so one verifier covers every platform artifact.
type Attestation struct {
	SHA256    string    `json:"sha256"`
	SignedAt  time.Time `json:"signed_at"`
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
}

// EvidencePack assembles the pack for a framework. Sign it next for the auditor copy.
func (g *GRC) EvidencePack(ctx context.Context, tenantID, framework string) (*EvidencePack, error) {
	cs, err := g.Posture(ctx, tenantID, framework)
	if err != nil {
		return nil, err
	}
	gaps := 0
	for _, c := range cs {
		if c.State == platform.ControlGap {
			gaps++
		}
	}
	return &EvidencePack{
		TenantID: tenantID, Framework: framework, GeneratedAt: g.now(),
		Controls: cs, GapCount: gaps,
	}, nil
}

// Sign computes the SHA-256 over the canonical pack (attestation stripped) and signs
// it. now is a clock injection point.
func Sign(p *EvidencePack, signer string, priv ed25519.PrivateKey, now time.Time) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("grc: invalid private key length %d", len(priv))
	}
	if signer == "" {
		return errors.New("grc: empty signer")
	}
	if p.GeneratedAt.IsZero() {
		p.GeneratedAt = now.UTC()
	}
	c, err := canon(p)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(c)
	sig := ed25519.Sign(priv, sum[:])
	p.Attestation = &Attestation{
		SHA256: hex.EncodeToString(sum[:]), SignedAt: now.UTC(),
		Signer: signer, Signature: hex.EncodeToString(sig),
	}
	return nil
}

// Verify checks a signed pack against pub.
func Verify(p *EvidencePack, pub ed25519.PublicKey) error {
	if p.Attestation == nil {
		return errors.New("grc: missing attestation")
	}
	c, err := canon(p)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(c)
	if hex.EncodeToString(sum[:]) != p.Attestation.SHA256 {
		return errors.New("grc: hash mismatch — pack altered after signing")
	}
	sig, err := hex.DecodeString(p.Attestation.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return errors.New("grc: signature verification failed")
	}
	return nil
}

func canon(p *EvidencePack) ([]byte, error) {
	clone := *p
	clone.Attestation = nil
	return json.Marshal(clone)
}

// frameworkControls explodes a finding's compliance annotation into framework→controls.
func frameworkControls(c *types.Compliance) map[string][]string {
	out := map[string][]string{}
	add := func(fw string, ids []string) {
		if len(ids) > 0 {
			out[fw] = ids
		}
	}
	add(FrameworkSOC2, c.SOC2)
	add(FrameworkISO27001, c.ISO27001)
	add(FrameworkPCI, c.PCI)
	add(FrameworkHIPAA, c.HIPAA)
	add(FrameworkCISv8, c.CISv8)
	add(FrameworkNISTCSF, c.NISTCSF)
	add(FrameworkGDPR, c.GDPR)
	add(FrameworkISO27701, c.ISO27701)
	add(FrameworkNIST80053, c.NIST80053)
	add(FrameworkNIST800171, c.NIST800171)
	add(FrameworkCCPA, c.CCPA)
	add(FrameworkSOX, c.SOX)
	add(FrameworkFedRAMP, c.FedRAMP)
	add(FrameworkDPDP, c.DPDP)
	add(FrameworkCMMC, c.CMMC)
	add(FrameworkISO42001, c.ISO42001)
	add(FrameworkNISTAIRMF, c.NISTAIRMF)
	return out
}
