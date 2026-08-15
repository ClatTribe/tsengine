# The benchmark box — per-asset recall on one machine

## The short version

**We were never missing benchmarks.** Every per-asset scorer is built (`tsbench run`,
`wavsep`, `sast`, `cloud`, `parity`) and every ground truth is committed —
`fixtures/web/wavsep/expected-cases.csv` is the full 1,133-case WAVSEP corpus,
`fixtures/cloud/baseline/expected-controls.csv` is the CIS set. What was missing is that
nothing ever **deployed the targets**.

`docker-compose.bench.yml` + `scripts/bench-box.sh` are that missing piece. On one box:

```bash
make sandbox-image     # once — the image with the ~20 OSS scanners
make bench-box         # deploy targets, score every asset, write a report, tear down
```

```bash
make bench-box-list    # what each asset needs, and which two have a neutral leaderboard
```

## Why each asset does or doesn't have a benchmark

The honest split is not "runnable vs not". It's **which assets have a neutral
third-party leaderboard to be measured against** — and that is only two.

| Asset | Benchmark | Target | Neutral leaderboard | Why not, where not |
|---|---|---|---|---|
| **web_application** | WAVSEP, 1,133 cases | `zaproxy/wavsep` container | **YES** — Acunetix 87%, Netsparker 87%, Burp 78%, WebInspect 76%, AppScan 69%, ZAP 56% (Shay Chen / sectoolmarket.com) | — |
| **repository (SAST)** | OWASP Benchmark v1.2, 2,740 cases | BenchmarkJava git clone | **YES** — Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6% | — |
| repository (SCA) | `fixtures/repo/sca-vuln` | none — tree is in-repo | no | Snyk/Dependabot self-publish against their own corpora; no shared corpus exists |
| container_image | `nginx-vuln` must-find CVEs | none — pulls the image | no | Trivy/Snyk/Anchore self-publish only |
| api | VAmPI must-find | `erev0s/vampi` container | no | **No neutral API-security benchmark exists.** Salt/Wallarm/Akto publish their own. The hardest API class (BOLA/BFLA) is business logic, so a shared corpus would have to encode each app's authorization policy — which is why nobody has built one |
| ip_address | open-port discovery | unauthenticated Redis container | no | Tenable/Qualys/Rapid7 publish no comparable scorecard |
| cloud_account | CIS controls, 42 in fixture | LocalStack (partial) or real creds | no | CSPM vendors (Prowler, Scout, Wiz, Orca) self-publish; no neutral CSPM leaderboard |
| **domain** | subdomain discovery | **cannot be hosted** | no | Enumeration queries *public* sources — crt.sh, passive DNS — about a *real registered* domain. There is nothing to put in a container. Measure against a domain you own whose subdomain set you know |
| FP-control (web/repo/container) | zero high+ findings | clean nginx / clean tree / alpine | n/a | The floor is zero by construction; specificity, not a competitor comparison |

Two things follow, and both matter for how the numbers get quoted:

1. **Only web and SAST produce a competitive claim.** Everything else is our own
   must-find set — a regression gate, genuinely useful, but not evidence of being better
   than anyone. Don't let the two categories get merged in a deck.
2. **Two assets can't reach a full number on a box at all.** `domain` has nothing to
   host. `cloud_account` on LocalStack exercises only the checks whose AWS APIs
   LocalStack implements — a subset of the 42 controls. The script reports that as
   `PARTIAL`, not as a CIS number.

## The safety model

The targets are deliberately vulnerable — WAVSEP is 1,133 working injection flaws, Juice
Shop ships RCE challenges. Co-locating them with the platform is safe only because of
three properties, all enforced in `docker-compose.bench.yml`:

1. **No published ports.** Every target uses `expose`, never `ports`. Nothing is
   reachable from the host, the VPC, or the internet.
2. **Targets share the sandbox bridge.** They join `tsengine-sandbox`, the network the
   ephemeral scan sandboxes attach to. Scanner→target works; host→target does not. This
   is also why readiness is probed from a throwaway container on that network rather than
   from the host — it proves the exact reachability the scanner will have.
3. **Profile-gated and torn down.** `profiles: ["bench"]` means a plain
   `docker compose up` cannot start a vulnerable app; `bench-box.sh` removes them on exit
   (`--keep-up` overrides, and says so loudly).

**Residual risk, stated plainly:** a target and the platform share one Docker bridge, so
RCE inside a target gives L3 reach to the platform container. That's the same accepted
single-box risk already documented for the sandboxes in `docker-compose.prod.yml`. It is
acceptable for a bench *run*; it is not acceptable to leave targets running
continuously next to production. If you want them always-on, use a separate box.

## EC2 sizing

WAVSEP (Tomcat + MySQL) and LocalStack dominate. Scans run concurrently with targets, and
the sandbox image is large.

| | Spec | Notes |
|---|---|---|
| Instance | **t3.xlarge** (4 vCPU / 16 GB) | t3.large works if you run assets one at a time |
| Disk | **60 GB gp3** | sandbox image + ~20 scanner corpora + WAVSEP + BenchmarkJava (~200 MB) + LocalStack |
| OS | Amazon Linux 2023 or Ubuntu 22.04+ | bash 4+; the script is written to also survive macOS bash 3.2 |
| Security group | **no inbound** for the bench box | targets are unpublished; you need nothing open. SSH via SSM |
| Egress | required | pulling images, cloning BenchmarkJava, scanner corpus refresh |

If the same box also runs the product (`docker-compose.prod.yml` — platform, frontend,
Postgres, Caddy), add roughly 4 GB and 20 GB. Prefer a **separate bench box**: it removes
the shared-bridge residual risk entirely, and a benchmark run saturates CPU in a way you
don't want touching a live tenant.

## What a run produces

`bench/results/<timestamp>/report.md`, plus a per-asset log. The report pins the sandbox
image digest and lists every asset as `OK` / `PARTIAL` / `SKIPPED` / `FAILED` — skips are
listed, never omitted, so the report can't be misread as full coverage.

One guard worth knowing about: a fixture with `runnable:false` makes `tsbench run` print a
stub **and exit 0**. Scoring on the exit code alone would record a pass for an asset that
never executed. The script greps for the stub marker and records `SKIPPED` instead.

## Still not measurable here

- **`domain` recall** — needs a real domain you own with a known subdomain set.
- **Full `cloud_account` CIS recall** — needs read-only credentials on a seeded AWS
  account. LocalStack gets a subset.
- **L2 agent recall** — a different axis: `make pentest-e2e` against Juice Shop and
  VAmPI, gated on `ANTHROPIC_API_KEY`, not on this box.
