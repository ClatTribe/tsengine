# ADR 0003 — SCA reachability via govulncheck (Go)

- **Status:** Proposed
- **Date:** 2026-06-20
- **Affects:** CLAUDE.md §5.3 (repository escalation), §13 (wrap-OSS); arch.md `repository`; the sandbox image (`docker/sandbox/Dockerfile`)

## Context

SCA (trivy / grype / osv-scanner) is the **noisiest detection class** in the
engine for false positives. Those tools flag **every** CVE in **every**
dependency in the lockfile — including vulnerabilities whose vulnerable code is
**never called** by the application. For a typical project, the majority of SCA
CVEs are in transitively-pulled code paths that are unreachable; surfacing them
all as actionable findings is the #1 SCA false-positive source, and the gap
competitors (Snyk Reachability, Endor Labs) sell against.

The accuracy track (PRs #203–#205) made FP measurable, controlled FP impact in
the VAPT report, and reduced fingerprint FP at the engine. **Reachability is the
remaining large FP lever** for SCA, and it was explicitly flagged as the next
gap.

## Decision

Wrap **govulncheck** — the Go team's official vulnerability scanner — as a
repository **escalation** tool (CLAUDE.md §5.3, signal-gated depth). govulncheck
does **call-graph analysis** and reports only the vulnerabilities whose
vulnerable symbol is actually reachable from the module's code. Those findings
are the **high-confidence, low-FP subset**:

- It does **not replace** the SCA tools — the L1 raw recall (every CVE) is
  unchanged (CLAUDE.md §2.4). govulncheck runs **in addition**, and the L1.5
  **corroborator** marks the CVEs that *both* an SCA tool and govulncheck report
  as agreed → the reachable ones rise in confidence, separating reachable (real)
  from unreachable (FP-prone) without dropping anything.
- It is **grounded** (§13): the leading OSS tool for the job, no in-house
  detector. The CVE rides in the `rule_id` so the L1.5 `threat_intel` hook
  enriches it (KEV/EPSS), matching trivy/grype.
- It is **signal-gated**: fires only when a finding indicates a Go project (a
  `.go` source finding, or an SCA finding located in `go.mod`/`go.sum`), so the
  expensive call-graph pass never runs on non-Go repos.

## The cost — sandbox Go toolchain

govulncheck's **source mode** (the precise, reachability-aware mode) needs the
**Go toolchain** present at runtime to build + analyse the module. The sandbox
runtime image (`ubuntu:22.04`) currently has **no Go toolchain** — it only
copies built binaries from the builder stage. Adding the toolchain is a real
image-size cost (~150–500 MB) for a Go-only capability. That trade-off is **why
this is an ADR** rather than a silent image change.

**Decision:** accept the toolchain add for the reachability value (Go is a
dominant SMB/startup language), implemented as a follow-up image change:
`COPY --from=builder /usr/local/go /usr/local/go` + `go install
golang.org/x/vuln/cmd/govulncheck@latest`, PATH-wired. Until that lands, the
wrapper **degrades gracefully** — `Run` returns the "binary missing" error as
output with no findings and never crashes the execute path (the standard
wrapper contract).

## What this ADR ships now (host-verified)

- `internal/tool/govulncheck` — the wrapper + the **streaming-JSON reachability
  parser** (keeps only `called`/reachable OSVs; drops `imported`-but-not-called
  — the FP class). Unit-tested against a realistic `govulncheck -json` stream.
- Repository **registry tier** + **escalation trigger** (`go-project →
  govulncheck`), unit-tested (fires once on a Go signal, never on a non-Go repo).
- `cmd/tool-server` registration.

## Consequences / roadmap

- **Cross-language reachability** is the documented next step and is **not**
  uniform: govulncheck is Go-only. Reachability for JS/Python/Java has no single
  dominant free OSS tool today; candidates (e.g. OSV-Scanner's call analysis,
  language-specific tools) are a future ADR, not a silent in-house build.
- An **FP-control bench fixture** pairing an SCA recall case with a reachability
  case (a Go module with an unreachable CVE that govulncheck must *not* surface)
  is the natural measurement follow-up to PR #203's severity-gated FP bench.
