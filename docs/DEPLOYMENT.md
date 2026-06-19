# Deployment & operations

How to run tsengine as a service in production. The engine is two cooperating
processes — the **host** (`tsengine serve`, orchestrates) and the **sandbox** (the
`tsengine/sandbox` image, runs the OSS tools) — connected over the docker daemon.

## Quick start — the product stack (docker compose)

The multi-tenant **platform** (`cmd/platform`, API + `/ui` on :8090) and the **frontend**
(Next.js UX on :3000) come up together:

```sh
cp .env.example .env
# set TSENGINE_SECRET_KEY:  openssl rand -base64 32
docker compose up --build       # or: make up
# → console  http://localhost:3000   (create a workspace at /signup)
# → API/ui   http://localhost:8090
```

Images: `docker/platform/Dockerfile` (Go, ~108MB) + `frontend/Dockerfile` (Next standalone,
~105MB). The platform persists to a named volume (`platform-data:/data`).

By default the stack runs **without the sandbox engine** (`TSENGINE_PLATFORM_NO_ENGINE=1`):
auth, dashboard, approvals, compliance, and identity/workspace ("operate") scanning all
work; **tech-asset (repo/web/cloud) scanning needs the engine**. To enable it, build the
sandbox (`make sandbox-image`), set `TSENGINE_PLATFORM_NO_ENGINE=0` on the `platform`
service, and uncomment the Docker-socket mount in `docker-compose.yml` (the platform shells
out to `docker run` to spawn per-scan sandboxes — see below).

**Not yet production-grade** (tracked): the store is single-node file-backed (sqlite/Postgres
is the successor behind the `store.Store` interface); secrets use an env AES key (cloud-KMS
is the successor behind `secret.Vault`); there is no bundled TLS/reverse-proxy or HA
orchestration. Put the stack behind a TLS-terminating proxy and back up the `platform-data`
volume.

---

## Architecture at runtime

```
        ┌─────────────────────────┐         spawns per-scan        ┌────────────────────────┐
 client │  tsengine host (serve)  │ ── docker run ───────────────▶ │  tsengine/sandbox:<tag>│
  ──────▶  :8080  /replay /healthz │ ◀── HTTP tool-server (per-scan) │  nuclei sqlmap trivy … │
        └─────────────────────────┘                                └────────────────────────┘
                    │ needs access to a Docker daemon (socket or DOCKER_HOST)
```

The host has **no security-tool binaries** by design (CLAUDE.md §12). It shells out
to `docker run` to spawn a sandbox container per scan, talks to its tool-server over
HTTP, and tears it down. So the host **must** reach a Docker daemon.

## Configuration

All flags have env equivalents; flags win.

| Env | Flag | Default | Purpose |
|---|---|---|---|
| `TSENGINE_API_TOKEN` | `--token` | — (**required**) | bearer token for `POST /replay`. The service refuses to start without it. |
| `TSENGINE_ADDR` | `--addr` | `:8080` | listen address |
| `TSENGINE_RUNS_DIR` | `--runs` | `runs` | where completed scans live (read by `/replay`) |
| `TSENGINE_SANDBOX_IMAGE` | `--image` | (digest from scan) | sandbox image ref for replay dispatch |
| `LLM_API_KEY` | — | — | the agent brain (cloud/web/llm-redteam). Sent only in the provider header; never logged. |
| `STRIX_LLM` | — | `gemini-2.0-flash` | `[provider/]model` for the agent brain |
| `TSENGINE_THREAT_INTEL_CORPUS` | — | embedded snapshot | path to the refreshed KEV+EPSS corpus |
| `TSENGINE_TOOL_TIMEOUT` | — | off | opt-in per-tool wall-clock cap |
| `TSENGINE_DISPATCH_CONCURRENCY` | — | `4` | bounded tool-dispatch concurrency |

Generate a token: `openssl rand -hex 24`. Store it in your platform's secret
manager, not in the image.

## Run

### Docker (with the daemon socket)

```bash
docker run -d --name tsengine \
  -p 8080:8080 \
  -e TSENGINE_API_TOKEN="$TSENGINE_API_TOKEN" \
  -e LLM_API_KEY="$LLM_API_KEY" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/runs:/data/runs" \
  ghcr.io/clattribe/tsengine/host:latest
```

Mounting the docker socket grants the container control of the host daemon — treat
the host image as privileged. Prefer a **scoped / rootless** daemon or a remote
`DOCKER_HOST` over the bare socket where you can (see Hardening).

### Kubernetes

Probes map directly:

```yaml
livenessProbe:  { httpGet: { path: /healthz, port: 8080 }, periodSeconds: 30 }
readinessProbe: { httpGet: { path: /readyz,  port: 8080 }, periodSeconds: 10 }
```

The sandbox-spawn model needs a Docker daemon. On k8s that means a rootless DinD
sidecar (or a node-level daemon via `DOCKER_HOST`) — **not** the cluster's CRI.
Inject `TSENGINE_API_TOKEN`/`LLM_API_KEY` from a `Secret`; mount `runs` on a PVC if
you want replay to outlive a restart.

## Health & verification

```bash
curl -fsS localhost:8080/healthz     # → ok
curl -fsS localhost:8080/version     # → {"version":"v0.5.0"}
# replay requires the token:
curl -fsS -X POST localhost:8080/replay \
  -H "Authorization: Bearer $TSENGINE_API_TOKEN" \
  -d '{"scan_id":"<id>","tool":"sqlmap_runner","args":{"--tamper":"space2comment"}}'
```

`/healthz` is liveness (process up). `/readyz` is readiness (runs dir writable);
it returns `503` if storage is unavailable so a load balancer drains the instance.

## Observability (platform)

The platform server (`cmd/platform`, `:8090`) emits structured logs and Prometheus
metrics with no external infrastructure required.

- **Logs** go to stderr. `TSENGINE_LOG_FORMAT=json` (recommended in prod) switches the
  default handler from human-readable text to JSON; `TSENGINE_LOG_LEVEL` sets the floor
  (`debug`/`info`/`warn`/`error`, default `info`). Every request is logged as a
  `http_request` line (method, path, status, `dur_ms`); 4xx → warn, 5xx → error. Setting
  the default handler also routes the existing `log.Print` startup/operational lines
  through the same structured output.
- **Metrics** are exposed at `GET /metrics` in Prometheus text format:
  - `tsengine_http_requests_total{method,code}` — request counts
  - `tsengine_http_request_duration_seconds{method}` — latency histogram
  - `tsengine_scan_jobs_inflight` — background scans queued + running (watch for backlog)
  - the standard Go runtime + process collectors (`go_goroutines`, `go_memstats_*`,
    process CPU/FDs) — the leak/saturation signals for a long-running single box

```bash
curl -fsS localhost:8090/metrics | grep tsengine_
```

`/metrics` is **not** auth-gated (standard Prometheus practice) — keep it on a private
network/interface or behind a reverse-proxy ACL. It and `/healthz` are excluded from the
access log to avoid scrape/health-check noise.

## Scaling & state

The host is **stateless** apart from the `runs` directory. Run N replicas behind a
load balancer; pin `runs` to shared storage (NFS/EFS/PVC) so `/replay` reaches any
scan regardless of which replica served it. Each scan spawns its own sandbox
container, so concurrency is bounded by daemon capacity + `TSENGINE_DISPATCH_CONCURRENCY`.

The durable **findings DB** (`tsengine findings`) and the multi-tenant store are a
separate layer (roadmap §4) — today findings persistence is a JSON file you point
the CLI at; a hosted store is future work.

## Security hardening

- **API token** is mandatory and compared in constant time; it is never logged.
  Rotate it via your secret manager.
- **Terminate TLS at the ingress** (the service speaks plain HTTP). Don't expose
  `:8080` publicly without a TLS proxy.
- **Docker socket = root-equivalent.** Use a rootless/scoped daemon, a remote
  `DOCKER_HOST`, or socket-proxy with a deny-by-default ruleset. Network-isolate the
  sandbox (`--network` policy) for active scanning.
- **Egress**: active web/api scanning and the agent brain make outbound requests.
  Allowlist destinations; the web agent additionally enforces a host allowlist +
  request cap structurally (never LLM-trusted).
- **Signing key**: attestations are signed with a persistent ed25519 key
  (`internal/attest`, default under the user config dir). Mount it from a secret and
  back it up — distribute the public half to auditors for `verify` / `web-verify`.

## Releases

Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`:

1. cross-platform binaries (`linux/darwin` × `amd64/arm64`) + `checksums.txt`,
   attached to a GitHub Release, version stamped via `-X main.Version`.
2. the host image built for `linux/amd64,arm64` and pushed to
   `ghcr.io/<repo>/host:<tag>` + `:latest` (auth via the built-in `GITHUB_TOKEN` —
   no extra secrets).

The sandbox image is built/published separately (`make sandbox-image`) and pinned
per scan by digest in `vulnerabilities.json` for reproducible replay.

## Upgrades

The host and sandbox version independently. A scan records the sandbox image digest
it used; `/replay` re-spawns **that** digest, so replays stay reproducible even after
you roll the host forward. Roll the sandbox image on its own cadence (corpus
refreshes via `tsengine corpus refresh`, out of band — CLAUDE.md §7).
