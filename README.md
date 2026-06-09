# tsengine

Go-native, two-layer security + compliance engine with **evidence-grounded autonomous agents**.

- **L1** — complete OSS vulnerability discovery across 7 asset types (nuclei, sqlmap, semgrep, trivy, prowler, …), wave-ordered fan-out, L1.5 enrichment (FP filter, corroboration, threat-intel KEV/EPSS, compliance mapping), signed evidence.
- **L2 agents** — LLM brain + deterministic tools, **grounded** (a finding is recorded only when a deterministic indicator backs it, never asserted):
  - **cloud** (`cloud-investigate`) — attack-path reachability + verified remediation.
  - **web/API** (`web-investigate`) — live exploitation; SQLi/XSS/open-redirect/path-traversal/cmdi; signed evidence bundle.
  - **LLM red-team** (`llm-redteam`) — jailbreak / secret-leak / tool-misuse, verified by tripwire.

Each agent ships with an **anti-circularity bench** (procedurally-generated vulnerable + decoy targets): 100% recall, 0 false positives across seeds — the grounding is proven, not claimed.

Paired with `webappsec` (the SaaS wrapper that consumes tsengine output and talks to the service's `/replay` API).

## Quickstart

```bash
# build the version-stamped CLI
make cli                      # → ./bin/tsengine
./bin/tsengine version

# build the sandbox image (OSS tools live here, not on the host)
make sandbox-image            # → tsengine/sandbox:0.1.0

# run a scan
./bin/tsengine scan --asset web_application --target https://example.com --image tsengine/sandbox:0.1.0

# turn any output into a branded report; track it over time
./bin/tsengine report   --in runs/<id>/vulnerabilities.json --format html --out report.html
./bin/tsengine findings ingest --db findings.json --in runs/<id>/vulnerabilities.json
./bin/tsengine findings list   --db findings.json --open --overdue
```

## Run as a service

The deployable surface (the tool-replay API webappsec calls) is `tsengine serve`:

```bash
export TSENGINE_API_TOKEN=$(openssl rand -hex 24)
./bin/tsengine serve --addr :8080 --runs runs --image tsengine/sandbox:0.1.0
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness probe |
| `GET /readyz` | none | readiness probe (runs dir writable) |
| `GET /version` | none | build identity |
| `POST /replay` | bearer | re-fire a tool against an existing scan (CLAUDE.md §9) |

Container image (`tsengine serve` + docker CLI baked in):

```bash
make host-image               # → tsengine/host:dev
docker run -p 8080:8080 \
  -e TSENGINE_API_TOKEN=$(openssl rand -hex 24) \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/runs:/data/runs" \
  tsengine/host:dev
```

Full operations guide — env vars, the docker-socket model, scaling, security hardening, k8s probes, release process — in **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Read first

- [CLAUDE.md](CLAUDE.md) — canonical architecture invariants (host/sandbox boundary, L1/L2 layers, ≤12-tool L2 cap, evidence grounding §10, build phases).
- [arch.md](arch.md) — per-asset architecture matrix (anchors, registry, filters, benches).
- [roadmap.md](roadmap.md) — what's built vs. what's left (toward the AI-native security agency).
- [benchmark.md](benchmark.md) — recall benches + the anti-overfit agent evals.

## Commands

`scan` · `replay` · `serve` · `report` · `findings` · `import` · `export` · `reachability` · `gate` · `correlate` · `web-investigate` / `web-verify` · `cloud-investigate` / `cloud-assess` · `llm-redteam` · `pubkey` / `verify` · `corpus` · `version`. Run `tsengine` with no args for usage.

**Prioritization:** `tsengine correlate --in webscan.json --in cloudscan.json` stitches findings *across* assets into a single attack chain to a crown jewel (e.g. a web SQLi that leaks an AWS key → the cloud IAM user it maps to → privilege escalation to admin) — grounded by the shared identifier, so no shared id means no chain.

**Shift-left / CI:** `tsengine import` pulls in another scanner's output (SARIF / Snyk / GitHub Dependabot); `tsengine reachability` answers "does our code actually call the vulnerable dependency function?"; `tsengine gate` turns scan / web-exploit / SCA-reachability findings into a **pass/fail** for your pipeline (gates on *proof*, not raw CVSS). So your existing Snyk/CodeQL results get the grounding + gate treatment. See **[docs/CI.md](docs/CI.md)** + the reusable `.github/actions/tsengine-gate` Action.

**Outbound handoff:** `tsengine export --in scan.json --format sarif` emits **SARIF 2.1.0** so GitHub code-scanning (or any SARIF consumer) shows tsengine's *proven* findings inline on the PR (`[verified]` prefix, `security-severity` + CWE tags, file:line locations). `tsengine export --in scan.json --webhook <url> [--webhook-token … --hmac-secret …]` POSTs a normalized, **signed** (Bearer + HMAC-SHA256) finding/case event to a SIEM / SOC / AI-SOC / ticketing endpoint. The OUT mirror of `import` — tsengine is a finding *source*, not just a sink.

## Develop

```bash
make all          # build + test + vet
make lint         # golangci-lint
go test ./...     # everything is unit-testable without infra (agents run a deterministic prober when no LLM key)
```

CI runs test (`-race`), vet, lint, and govulncheck on every PR. Direct push to `main` is blocked — ship via PR.
