# Production single-box deployment — design & threat model

> **Status:** design (Phase 0). Implementation lands phase-by-phase (§5); each phase is a
> PR and updates its row here as it ships.

This is the plan to run the whole tsengine product — platform API, console/UX, **and**
real OSS-tool scans against potentially-hostile customer assets — safely on **one
machine**. It is the honest, security-first answer to "is it production ready?": the
product *logic* is comprehensive and verified; what this work adds is the **deployment
hardening** so a single box can run it without the box (or one customer's data) being
compromised by another customer's scan.

The architecture is already designed to scale out (every storage/secret/queue seam is an
interface — §6); this doc is explicitly about the **single-box** target. The
scale-to-many-machines gaps are catalogued in §6 so they're not forgotten.

---

## 1. What "production ready for single-box" means here

Three things, in priority order:

1. **Isolation & safety (the load-bearing requirement).** We run untrusted/uncontrolled
   inputs through OSS tools: a customer's source tree, a container image, a web app, an IP
   range. Any of those can be *malicious* (a poisoned repo that exploits a scanner; a target
   that attacks the scanner back) or simply *dangerous* (a scan that floods the box). A
   compromise of a scan **must not** reach: the host, the platform/DB, or **another
   customer's** assets or results. This is the part that makes us safe to point at real
   customer infrastructure.
2. **Runs everything on the box, including scans.** `docker compose up` brings up the
   platform + UX **and** can spawn the per-scan sandbox that runs nuclei/sqlmap/trivy/etc.
   Today the default stack ships `NO_ENGINE=1` (no tech-asset scanning); production single-box
   turns the engine on, safely.
3. **Operable.** TLS at the edge, secrets not in plaintext env, backups of the one stateful
   volume, health/restart, and a one-command deploy script.

---

## 2. Current state (grounded)

| Area | Today | File |
|---|---|---|
| Stack | `docker-compose.yml`: platform `:8090` + frontend `:3000`, `platform-data` volume; **`NO_ENGINE=1`** by default | `docker-compose.yml` |
| Scan execution | host shells out to `docker run` to spawn an ephemeral per-scan sandbox, talks to its tool-server over HTTP on `127.0.0.1`, tears it down | `internal/sandbox/runtime.go` |
| Sandbox hardening (already present) | `--rm` (ephemeral), `--cap-drop=ALL`, `--security-opt no-new-privileges`, port bound to `127.0.0.1`, bind-mounts forced `:ro` | `buildRunArgs()` |
| Store | SQLite (ACID) / file snapshot on the volume | `internal/store` |
| Secrets | OAuth tokens AES-256-GCM sealed at rest; key from `TSENGINE_SECRET_KEY` (env) | `internal/secret` |
| Edge | **none** — ports published raw, no TLS | — |
| Engine enablement | requires mounting `/var/run/docker.sock` into the platform (commented) | `docker-compose.yml` |

### The two sharp edges

- **Sandbox not fully confined.** It already drops caps + privileges, but it still runs as
  **root** inside the container, with a **writable rootfs**, **no resource limits** (a fork
  bomb / memory hog / disk filler from a malicious target can starve the box), and on a
  **shared default network** (it can reach the host gateway and, depending on compose
  networking, sibling containers).
- **Docker-socket = host root.** To spawn sandboxes the platform needs the Docker API. The
  documented way mounts `/var/run/docker.sock` straight into the platform container — which
  is **root-equivalent on the host**. If the platform is ever compromised (a malicious
  payload in a finding, an SSRF, a deserialization bug), the attacker owns the machine. This
  is the single biggest single-box risk and §5 Phase 2 fixes it.

---

## 3. Threat model (single-box, multi-tenant)

**Assets to protect:** the host; the platform process + DB (all tenants' findings,
sealed tokens, the signing key); each tenant's scan inputs/outputs; the network path to
each tenant's *real* infrastructure.

**Adversaries / threats:**

| # | Threat | Vector | Mitigation (phase) |
|---|---|---|---|
| T1 | **Scanner exploited by a malicious target/repo** → code exec inside the sandbox | parsing a crafted artifact; a target that attacks back | Ephemeral container + cap-drop + no-new-priv (have); **read-only rootfs, non-root user, seccomp, pids/mem/cpu limits** (P1) |
| T2 | **Sandbox → host escape** | a container breakout from T1 | Minimise kernel attack surface (P1 hardening); **never give the sandbox the docker socket** (already true); rootless/socket-proxy so even an escape isn't host-root (P2) |
| T3 | **Platform compromise → host takeover** | the platform holds the docker socket | **Socket-proxy** restricting the Docker API to create/start/stop/rm on an internal network; platform never touches the raw socket (P2) |
| T4 | **Cross-tenant / lateral movement** | sandbox A reaches the DB, the frontend, or sandbox B / tenant B's network | **Per-scan isolated network**, no route to internal compose services; egress policy (P1/P2) |
| T5 | **Resource exhaustion / DoS the box** | a giant repo, a fork bomb, a runaway scan | `--memory/--cpus/--pids-limit/--ulimit` per sandbox + the existing `TSENGINE_TOOL_TIMEOUT` + dispatch concurrency cap (P1) |
| T6 | **Secret exfiltration** | tokens/signing key read off disk or env | sealed-at-rest (have); secrets from file/Docker-secret not inline env (P4); sandbox can't read the platform volume (P1 network + no mount) |
| T7 | **Eavesdrop / MITM on the console** | raw HTTP on the LAN | **TLS edge** (Caddy) + HSTS/security headers (P3) |
| T8 | **Data loss** | volume/disk failure | **backup + restore** of `platform-data` (P4) |

**Explicitly out of scope for single-box** (accepted, documented in §6): a kernel-level
escape on a fully-patched host with all P1/P2 mitigations is treated as residual risk;
true defense-in-depth there is per-tenant VMs / microVMs (gVisor/Kata/Firecracker) — a
scale-tier item.

---

## 4. Target architecture (single-box, hardened)

```
                         ┌──────────── host machine ────────────┐
   Internet ──TLS──▶ caddy (edge, :443)                         │
                         │   ├─▶ frontend  (Next, internal)      │
                         │   └─▶ platform  (API/console, internal)
                         │              │ DOCKER_HOST=tcp://socket-proxy
                         │              ▼
                         │        docker-socket-proxy  (internal net; POST /containers only)
                         │              │ (talks to the real daemon)
                         │              ▼
                         │        per-scan SANDBOX  ── ephemeral, hardened ──┐
                         │        (read-only, non-root, capped, isolated net)│ runs nuclei/
                         │                                                   │ sqlmap/trivy…
   platform-data volume ─┘   (SQLite + signing key; NOT reachable by sandbox)
```

- The **edge** (Caddy) is the only published port; platform + frontend are internal.
- The **platform never holds the raw docker socket** — it speaks the Docker API through a
  **socket-proxy** that only permits the container lifecycle calls it needs, on an internal
  network.
- Each **sandbox** is ephemeral, hardened (P1), and on a network that can egress to scan
  targets but **cannot** reach the platform, the DB, the frontend, or sibling sandboxes.

---

## 5. Implementation phases (the build plan)

Each phase = one PR with tests; this table is the source of truth for status.

| Phase | Scope | Key deliverables | Status |
|---|---|---|---|
| **P0** | **Design** (this doc) | threat model + target arch + phased plan + scale-gaps | **this PR** |
| **P1** | **Sandbox hardening** | `buildRunArgs` adds `--read-only` + `--tmpfs` scratch, `--user`, `--pids-limit`, `--memory`, `--cpus`, `--ulimit`, `--network` policy; all env-tunable (`TSENGINE_SANDBOX_*`) with safe defaults; unit tests assert every flag | planned |
| **P2** | **De-privilege the daemon** | `docker-compose.prod.yml` with a `docker-socket-proxy` (internal net, create/start/stop/rm only); platform uses `DOCKER_HOST`; sandbox runs on an isolated network; nothing publishes the docker socket | planned |
| **P3** | **TLS edge** | Caddy service (auto-cert / local CA), security headers (HSTS, CSP-frame, nosniff), platform+frontend unpublished; only `:443` exposed | planned |
| **P4** | **Secrets + backups + deploy script** | secrets from file/Docker-secret (not inline env) + rotation note; `scripts/backup.sh`/`restore.sh` for `platform-data`; **`scripts/deploy-single-box.sh`** (prereq check → gen secrets → build images incl. sandbox → up hardened stack → smoke test) | planned |
| **P5** | **Verify + docs finalize** | end-to-end smoke on the hardened stack incl. a real sandbox scan; finalize this doc's deploy runbook (§7); CLAUDE.md + DEPLOYMENT.md cross-links | planned |

---

## 6. Scale gaps — what single-box does NOT give you (multi-machine prod)

These are deliberately out of scope here; each already has a seam in the code so it swaps in
without touching call sites:

- **State:** single-node SQLite/file store → **Postgres** (`store.Store` successor). No HA,
  no read replicas, no failover today.
- **Secrets:** env/file AES key → **cloud-KMS** (`secret.Vault` successor) with managed
  rotation + per-tenant keys.
- **Scan execution:** one box's Docker daemon → a **sandbox pool / scheduler** across nodes
  (k8s with rootless DinD or Firecracker microVMs per tenant), with a **durable job queue**
  (the in-proc `internal/jobs` pool → Redis/NATS/SQS).
- **Stronger isolation tier:** containers → **microVM / gVisor (Kata, Firecracker)** per
  scan for kernel-escape defense-in-depth (T2/T4 residual risk).
- **Artifacts:** local `runs` dir → object storage (S3/GCS) so replay outlives any node.
- **Edge:** single Caddy → load-balanced, multi-replica, WAF, per-tenant rate-limit store.
- **Observability:** `/metrics` scrape → centralized Prometheus + tracing (OTel) + alerting.

---

## 7. Single-box deploy runbook (filled in as phases land)

> Populated by P4/P5. The short version it builds toward:
> ```sh
> ./scripts/deploy-single-box.sh        # prereqs, secrets, build (incl. sandbox), up, smoke
> # → https://<host>/   (create the first workspace at /signup)
> ```
> with the hardened `docker-compose.prod.yml` (edge TLS, socket-proxy, isolated sandbox
> network, engine ON), the `platform-data` volume backed up by `scripts/backup.sh`.
