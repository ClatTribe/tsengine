# CI/CD security gate

`tsengine gate` turns the engine's findings into a **pass/fail** that blocks a merge
— the Shift-Left entry point. It is deliberately low-noise:

- **Gates on proof, not labels.** A finding blocks when the engine *proved* it — a
  **verified exploit** (web agent re-confirmed it) or a **reachable** dependency CVE
  (its vulnerable function is on a real call path). A vulnerable dependency you never
  call does **not** block, however "critical" its CVSS — that is the whole point of
  reachability triage (see [reachability](#sca-reachability-gate)).
- **Fail on new risk, not debt.** With a **baseline** + `--new-only`, only findings
  absent from the last accepted run gate the build.
- **Waivers.** Accept a finding by fingerprint, with a reason and optional expiry.

Exit code: `0` = pass, `1` = a policy violation (block the merge).

## Policy

Defaults (`tsengine gate` with no policy flags):

| Rule | Default | Meaning |
|---|---|---|
| `--fail-on <sev>` | `high` | any **non-SCA** finding at this severity or worse fails |
| `--fail-on-verified` | `true` | any verified/proven-exploitable finding fails |
| `--fail-on-reachable` | `true` | any **reachable** dependency CVE fails (SCA gates on reachability only) |
| `--max-new <N>` | `-1` (off) | fail if NEW findings exceed N |
| `--new-only` | `false` | gate only on findings absent from `--baseline` |

Or supply a JSON `--policy` file (flags override its fields):

```json
{
  "fail_on_severity": "high",
  "fail_on_verified": true,
  "fail_on_reachable_sca": true,
  "max_new_findings": 0,
  "new_only": true,
  "waivers": [
    { "fingerprint": "g-1a2b3c4d5e6f", "reason": "accepted; compensating control", "expires": "2026-12-31T00:00:00Z" }
  ]
}
```

## GitHub Actions

Use the bundled composite action:

```yaml
# .github/workflows/security-gate.yml
name: security gate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # produce findings however you like, e.g. an SCA findings file + this repo,
      # and/or a prior tsengine scan / web-investigate evidence bundle:
      # - run: trivy fs --format json -o sca.json .   (then map to {package,symbols,severity})

      - name: tsengine security gate
        uses: ClatTribe/tsengine/.github/actions/tsengine-gate@main
        with:
          sca: sca.json
          repo: .
          fail-on: high
          # baseline: .tsengine/baseline.json
          # new-only: "true"
```

Violations surface inline on the PR as `::error::` annotations; a failing gate fails
the job and blocks the merge.

## GitLab CI

```yaml
security-gate:
  image: golang:1.25
  script:
    - go install github.com/ClatTribe/tsengine/cmd/tsengine@latest
    - tsengine gate --sca sca.json --repo . --fail-on high
  # non-zero exit fails the job
```

## SCA reachability gate

The highest-signal gate. Feed it your scanner's dependency findings (package +
optional vulnerable symbols + severity) and the repo; it blocks **only** the ones
whose vulnerable function is actually reachable from an entrypoint:

```bash
tsengine gate --sca sca.json --repo .
# ✗ [HIGH] CVE-2026-1 in crypto/ed25519 (sca) — reachable dependency vulnerability
#   (the unreachable "critical" CVE in an unused dep does NOT block)
```

`sca.json` shape: `[{ "id", "cve", "package", "symbols": ["Fn"], "severity" }]`.
Reachability is Go-first today (other languages are new extractors).

## Baseline workflow (fail on new only)

```bash
# 1. snapshot the currently-accepted findings, then commit the file. The baseline is
#    written regardless of the gate verdict, so the exit code here doesn't matter.
tsengine gate --sca sca.json --repo . --save-baseline .tsengine/baseline.json || true

# 2. in CI, gate only on NEW risk vs that baseline
tsengine gate --sca sca.json --repo . --baseline .tsengine/baseline.json --new-only
```

Refresh the baseline when you intentionally accept new findings.
