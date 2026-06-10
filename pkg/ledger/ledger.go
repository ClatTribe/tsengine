// Package ledger is the replayable agent decision ledger (roadmap §9): it persists
// and signs every step an autonomous agent takes — the model's thought, the tool it
// chose, the arguments, and the deterministic observation that came back — into a
// tamper-evident, replayable record. Parity with an AI-SOC's "Investigation Ledger":
// an auditor can replay exactly what the agent did and why, and verify the record was
// not altered after signing.
//
// The package is a LEAF: it imports only the standard library. The three agent
// flavors (webagent, cloudagent, llmredteam) import it and attach a *Recorder to
// their loop; it never imports them back, so there is no cycle. The signing scheme
// mirrors internal/webagent.SignEvidence — SHA-256 over canonical JSON + ed25519 —
// so the same key/verify tooling (internal/attest, `tsengine pubkey`) covers it.
package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is the ledger format version, pinned into every record so an older
// verifier can refuse a format it does not understand.
const SchemaVersion = "tsengine-ledger/1"

// Step is one ReAct step: the model's decision (its thought + the tool it chose +
// the arguments) and the DETERMINISTIC observation the tool returned. The ordered
// Steps are the replayable decision trail — what the agent did, in order, and why.
type Step struct {
	Seq         int            `json:"seq"`
	At          time.Time      `json:"at"`
	Thought     string         `json:"thought,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	Args        map[string]any `json:"args,omitempty"`
	Observation string         `json:"observation,omitempty"`
	// Note records a non-dispatch step (a malformed action, an unknown tool) so the
	// trail has no silent gaps — the record reflects every model turn, not only the
	// ones that resolved to a tool.
	Note string `json:"note,omitempty"`
}

// Decision is one grounded commitment the agent made — a recorded finding (web),
// attack-path issue (cloud), or breach (LLM red-team). It is the OUTCOME the step
// trail produced, normalized across agent flavors: every commitment cites the
// evidence that grounded it (turn IDs / a reachability path), so the ledger shows
// not just what was decided but what backed it.
type Decision struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"` // vuln class | "attack_path" | breach class
	Severity string   `json:"severity,omitempty"`
	Refs     []string `json:"evidence_refs,omitempty"` // grounding: turn IDs / graph path
	Detail   string   `json:"detail,omitempty"`        // rationale
}

// Attestation is the signature block (SHA-256 of canonical JSON + ed25519), mirroring
// webagent.EvidenceAttest so one verifier covers both artifacts.
type Attestation struct {
	SHA256    string    `json:"sha256"`
	SignedAt  time.Time `json:"signed_at"`
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
}

// Ledger is the durable, signed record of one agent engagement.
type Ledger struct {
	Version      string       `json:"version"`
	EngagementID string       `json:"engagement_id,omitempty"`
	AgentKind    string       `json:"agent_kind"` // webagent | cloudagent | llmredteam
	Target       string       `json:"target,omitempty"`
	Engine       string       `json:"engine,omitempty"`
	StartedAt    time.Time    `json:"started_at"`
	CompletedAt  time.Time    `json:"completed_at,omitempty"`
	Steps        []Step       `json:"steps"`
	Decisions    []Decision   `json:"decisions"`
	Summary      string       `json:"summary,omitempty"`
	Attestation  *Attestation `json:"attestation,omitempty"`
}

// --- Recorder: the live capture hook the agent loop calls each step ---

// Recorder accumulates the ReAct steps of one engagement. It is nil-safe by design:
// every method tolerates a nil *Recorder, so an agent loop can call it
// unconditionally and a caller that did not opt in pays nothing. The clock is
// injectable for deterministic tests.
type Recorder struct {
	mu    sync.Mutex
	steps []Step
	n     int
	now   func() time.Time
}

// NewRecorder returns a Recorder stamping wall-clock time on each step.
func NewRecorder() *Recorder { return &Recorder{now: time.Now} }

// WithClock overrides the timestamp source (tests pin it for determinism).
func (r *Recorder) WithClock(now func() time.Time) *Recorder {
	if r != nil && now != nil {
		r.now = now
	}
	return r
}

func (r *Recorder) stamp() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

// Record appends one dispatched step: the model's thought, the tool it chose, the
// arguments, and the tool's observation. No-op on a nil receiver.
func (r *Recorder) Record(thought, tool string, args map[string]any, observation string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	r.steps = append(r.steps, Step{
		Seq: r.n, At: r.stamp(), Thought: thought, Tool: tool,
		Args: cloneArgs(args), Observation: observation,
	})
}

// Note appends a non-dispatch step (malformed action, unknown tool) so the trail is
// complete. No-op on a nil receiver.
func (r *Recorder) Note(note string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	r.steps = append(r.steps, Step{Seq: r.n, At: r.stamp(), Note: note})
}

// Steps returns a copy of the recorded steps in order. Nil-safe (returns nil).
func (r *Recorder) Steps() []Step {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Step, len(r.steps))
	copy(out, r.steps)
	return out
}

// Len is the number of recorded steps. Nil-safe (returns 0).
func (r *Recorder) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.steps)
}

// Meta carries the engagement-level fields the Recorder cannot know on its own.
type Meta struct {
	EngagementID string
	AgentKind    string
	Target       string
	Engine       string
	Summary      string
	StartedAt    time.Time
	CompletedAt  time.Time
	Decisions    []Decision
}

// Build assembles a Ledger from the recorded steps plus engagement metadata
// (including the grounded Decisions the caller maps from the agent's report). The
// result is unsigned — call Sign next. Nil-safe (an empty recorder yields an empty
// step trail, not a panic).
func (r *Recorder) Build(m Meta) *Ledger {
	l := &Ledger{
		Version:      SchemaVersion,
		EngagementID: m.EngagementID,
		AgentKind:    m.AgentKind,
		Target:       m.Target,
		Engine:       m.Engine,
		StartedAt:    m.StartedAt.UTC(),
		Steps:        r.Steps(),
		Decisions:    append([]Decision(nil), m.Decisions...),
		Summary:      m.Summary,
	}
	if !m.CompletedAt.IsZero() {
		l.CompletedAt = m.CompletedAt.UTC()
	}
	if l.Steps == nil {
		l.Steps = []Step{}
	}
	if l.Decisions == nil {
		l.Decisions = []Decision{}
	}
	return l
}

// cloneArgs deep-copies the args map so a later mutation of the agent's args by the
// loop cannot retroactively alter a recorded step.
func cloneArgs(args map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	// Round-trip through JSON: args originate from a parsed JSON action, so this is a
	// faithful, value-stable deep copy (and keeps the canonical form deterministic).
	b, err := json.Marshal(args)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// --- signing / verification (mirrors webagent.SignEvidence) ---

// canon produces the canonical bytes signed/verified: the ledger with its
// Attestation block stripped. encoding/json sorts map keys, so the args maps
// serialise deterministically.
func canon(l *Ledger) ([]byte, error) {
	clone := *l
	clone.Attestation = nil
	return json.Marshal(clone)
}

// Sign computes the SHA-256 over the canonical ledger and signs it, populating the
// Attestation block. now is a clock injection point (tests pin it).
func Sign(l *Ledger, signer string, priv ed25519.PrivateKey, now time.Time) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ledger: invalid private key length %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if signer == "" {
		return errors.New("ledger: empty signer")
	}
	if l.StartedAt.IsZero() {
		l.StartedAt = now.UTC()
	}
	c, err := canon(l)
	if err != nil {
		return fmt.Errorf("ledger: canonical: %w", err)
	}
	sum := sha256.Sum256(c)
	sig := ed25519.Sign(priv, sum[:])
	l.Attestation = &Attestation{
		SHA256:    hex.EncodeToString(sum[:]),
		SignedAt:  now.UTC(),
		Signer:    signer,
		Signature: hex.EncodeToString(sig),
	}
	return nil
}

// Verify checks the ledger's attestation against pub. Returns nil iff the record is
// intact and the signature is valid — proving no step was added, dropped, or altered
// after signing.
func Verify(l *Ledger, pub ed25519.PublicKey) error {
	if l.Attestation == nil {
		return errors.New("ledger: missing attestation")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ledger: invalid public key length %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	c, err := canon(l)
	if err != nil {
		return fmt.Errorf("ledger: canonical: %w", err)
	}
	sum := sha256.Sum256(c)
	if want := hex.EncodeToString(sum[:]); l.Attestation.SHA256 != want {
		return fmt.Errorf("ledger: hash mismatch (got %s, want %s) — record was altered after signing", l.Attestation.SHA256, want)
	}
	sig, err := hex.DecodeString(l.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("ledger: signature decode: %w", err)
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return errors.New("ledger: signature verification failed")
	}
	return nil
}

// Export writes the ledger as indented JSON to path (creating parent dirs).
func Export(path string, l *Ledger) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Load reads a ledger from path.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("ledger: decode: %w", err)
	}
	return &l, nil
}

// --- replay ---

// Replay reconstructs the agent's decision sequence as an ordered, human-readable
// transcript directly from the (verified) record — the "replayable" half of the
// ledger. It is a pure function of the Steps, so a reviewer sees exactly the thought
// → tool(args) → observation chain the agent executed, with no live model required.
func Replay(l *Ledger) []string {
	out := make([]string, 0, len(l.Steps)+len(l.Decisions)+2)
	for _, s := range l.Steps {
		if s.Note != "" {
			out = append(out, fmt.Sprintf("#%d  ⚠ %s", s.Seq, s.Note))
			continue
		}
		line := fmt.Sprintf("#%d  %s(%s)", s.Seq, s.Tool, compactArgs(s.Args))
		if t := strings.TrimSpace(s.Thought); t != "" && t != "playbook" {
			line += "\n     ↳ thought: " + oneLine(t, 200)
		}
		if o := strings.TrimSpace(s.Observation); o != "" {
			line += "\n     ⇒ " + oneLine(o, 280)
		}
		out = append(out, line)
	}
	if len(l.Decisions) > 0 {
		out = append(out, "── grounded decisions ──")
		for _, d := range l.Decisions {
			refs := ""
			if len(d.Refs) > 0 {
				refs = " evidence=[" + strings.Join(d.Refs, ",") + "]"
			}
			sev := ""
			if d.Severity != "" {
				sev = " " + d.Severity
			}
			out = append(out, fmt.Sprintf("  • %s (%s%s)%s", d.ID, d.Kind, sev, refs))
		}
	}
	return out
}

// compactArgs renders an args map as a stable, single-line k=v list (keys sorted).
func compactArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, oneLine(fmt.Sprintf("%v", args[k]), 80)))
	}
	return strings.Join(parts, ", ")
}

func oneLine(s string, max int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
