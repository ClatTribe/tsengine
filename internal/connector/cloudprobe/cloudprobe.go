// Package cloudprobe is the SDK-isolated home for the provider policy-simulator dry-run that backs
// cloudagent.ExploitProber (ADR 0024 P1). It is a SEPARATE package for the same reason the *remediate
// packages are: cloudagent must stay SDK-free, so the real AWS/GCP/Azure client imports live here and
// are adapted into cloudagent's SDK-free ProbeResult shape at the call site.
//
// The dry-run is READ-ONLY and benign by construction — it asks the provider's own policy engine
// "would this be allowed?" and performs nothing:
//   - AWS   iam.SimulatePrincipalPolicy(PolicySourceArn=principal, ActionNames=[action], ResourceArns=[resource])
//   - GCP   iam.testIamPermissions / resourcemanager Projects.TestIamPermissions
//   - Azure authorization CheckAccess (Microsoft.Authorization/checkAccess)
//
// This file ships the SHAPE and a deterministic fake so the wiring, the tool, and the grounding can be
// tested offline. The three live SDK adapters are the follow-on (each gated on the read-only session
// already assumed with cloudsafety.SessionPolicy — SimulatePrincipalPolicy needs iam:SimulatePrincipalPolicy,
// which is a READ permission, so it fits inside the existing read-only cross-account role).
package cloudprobe

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
)

// Decision is the provider's raw evaluation decision for one (principal, action, resource) tuple,
// SDK-free so callers below the seam don't leak cloud types upward.
type Decision struct {
	// Allowed is the provider's answer; Known is false when the simulator could not decide (no
	// permission to simulate, unmodelled action) — so a false/false pair is UNKNOWN, never DENY.
	Allowed bool
	Known   bool
	Detail  string // which statement matched / the provider's decision string
	Why     string // why Known is false, when it is
}

// Simulator is the provider-specific dry-run, implemented by an AWS/GCP/Azure adapter (below the SDK
// seam). One method: evaluate a tuple, mutate nothing.
type Simulator interface {
	Simulate(ctx context.Context, principal, action, resource string) (Decision, error)
	// Describe returns a one-line coverage string (provider + whether the simulate permission is held).
	Describe() string
}

// Prober adapts a provider Simulator into cloudagent.ExploitProber (the SDK-free shape the agent
// consumes). now is injectable so ProbedAt is deterministic in tests.
type Prober struct {
	Sim Simulator
	Now func() string // yields ProbedAt; nil → empty string (tests inject a fixed stamp)
}

var _ cloudagent.ExploitProber = (*Prober)(nil)

func (p *Prober) CanPerform(ctx context.Context, principal, action, resource string) (cloudagent.ProbeResult, error) {
	d, err := p.Sim.Simulate(ctx, principal, action, resource)
	if err != nil {
		return cloudagent.ProbeResult{Verdict: cloudagent.VerdictUnknown, ProbedAt: p.stamp(), Why: err.Error()}, err
	}
	res := cloudagent.ProbeResult{Detail: d.Detail, ProbedAt: p.stamp(), Why: d.Why}
	switch {
	case !d.Known:
		res.Verdict = cloudagent.VerdictUnknown
	case d.Allowed:
		res.Verdict = cloudagent.VerdictAllow
	default:
		res.Verdict = cloudagent.VerdictDeny
	}
	return res, nil
}

func (p *Prober) Coverage() string { return p.Sim.Describe() }

func (p *Prober) stamp() string {
	if p.Now == nil {
		return ""
	}
	return p.Now()
}

// FakeSimulator is a deterministic, in-memory Simulator for tests and offline wiring. Allow lists the
// (principal, action, resource) tuples the provider would permit; Deny lists explicit denies;
// anything else is UNKNOWN (the honest default — absence of a rule is not a deny).
type FakeSimulator struct {
	Allow  map[[3]string]string // tuple -> detail
	Deny   map[[3]string]bool
	NoPerm bool // simulate the "we can't run the simulator" case → every answer is UNKNOWN with Why
	Note   string
}

func (f FakeSimulator) Simulate(_ context.Context, principal, action, resource string) (Decision, error) {
	if f.NoPerm {
		return Decision{Known: false, Why: "no permission to run the policy simulator"}, nil
	}
	key := [3]string{principal, action, resource}
	if detail, ok := f.Allow[key]; ok {
		return Decision{Allowed: true, Known: true, Detail: detail}, nil
	}
	if f.Deny[key] {
		return Decision{Allowed: false, Known: true, Detail: "explicit deny"}, nil
	}
	return Decision{Known: false, Why: "no matching simulation rule"}, nil
}

func (f FakeSimulator) Describe() string {
	if f.Note != "" {
		return f.Note
	}
	return "fake simulator (offline)"
}
