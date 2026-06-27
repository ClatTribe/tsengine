// Package safechain is the install-time supply-chain guard — Aikido's "Safe Chain" parity (/Code pillar).
// The repository asset already DETECTS malicious dependencies in a committed lockfile (internal/supplychain
// + the malicious-packages tool); Safe Chain moves that one step earlier: it gives a yes/no verdict on a
// SINGLE package the moment someone is about to `npm install` / `pip install` it, so a hostile package is
// blocked BEFORE it lands on a developer machine or in a build — the gap between "we'd have caught it on the
// next scan" and "it never ran".
//
// It deliberately reuses supplychain.Scan as its decision oracle (the SAME grounded corpus), so the install
// gate and the lockfile scanner can never drift. Grounded (§10): a package is blocked ONLY on a real
// known-malicious corpus match; an unknown package is ALLOWED (fail-open — a guard must not block the whole
// ecosystem on absence of proof; a typosquat-distance heuristic is the documented next layer). The verdict
// is a CI/pre-install gate today; the npm/yarn/npx CLI shim that calls it is the gated half.
package safechain

import (
	"github.com/ClatTribe/tsengine/internal/supplychain"
)

// Verdict is the install-time decision for one package coordinate.
type Verdict struct {
	Package  string `json:"package"` // ecosystem:name@version
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`   // why it was blocked (human-readable)
	Advisory string `json:"advisory,omitempty"` // provenance of the block (the rule/advisory id)
}

// Result is a batch decision over an install manifest (e.g. every dependency `npm install` would add).
type Result struct {
	Verdicts []Verdict `json:"verdicts"`
	Blocked  int       `json:"blocked"` // how many were refused
	Checked  int       `json:"checked"`
	Safe     bool      `json:"safe"` // true ⇔ nothing was blocked (the install may proceed)
}

// Check decides whether a single about-to-be-installed package is safe. It runs the package through the
// exact malicious-package detector (supplychain.Scan over the supplied corpus) — a finding means block.
func Check(p supplychain.Package, corpus []supplychain.MaliciousPackage) Verdict {
	v := Verdict{Package: coord(p), Allowed: true}
	if findings := supplychain.Scan([]supplychain.Package{p}, corpus, supplychain.Options{}); len(findings) > 0 {
		v.Allowed = false
		v.Reason = findings[0].Description
		v.Advisory = findings[0].RuleID
	}
	return v
}

// CheckAll gates a whole install manifest and rolls up whether it is safe to proceed.
func CheckAll(pkgs []supplychain.Package, corpus []supplychain.MaliciousPackage) Result {
	r := Result{Checked: len(pkgs), Safe: true}
	for _, p := range pkgs {
		v := Check(p, corpus)
		r.Verdicts = append(r.Verdicts, v)
		if !v.Allowed {
			r.Blocked++
			r.Safe = false
		}
	}
	return r
}

func coord(p supplychain.Package) string {
	c := p.Name
	if p.Ecosystem != "" {
		c = p.Ecosystem + ":" + p.Name
	}
	if p.Version != "" {
		c += "@" + p.Version
	}
	return c
}
