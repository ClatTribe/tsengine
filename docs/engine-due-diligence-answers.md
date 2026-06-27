# Engine due-diligence: answers to the per-asset / per-framework questions

This doc answers, point by point, the security-engine due-diligence questions a buyer, MSP partner, or
auditor asks — and that drove the #602–#627 engine-audit campaign. Every claim cites the package/PR that
backs it, and every honest gate (credential / infra / product decision) is stated plainly (§10 — we never
claim a capability we don't have).

The product serves **two GTM models off one engine**: (1) **MSP/consulting channel** — the partner runs the
product, their expert performs the human-in-the-loop (HITL); (2) **managed consultant** — we hire the expert,
ICP = a founder who needs security + compliance. The only difference is *who employs the HITL human* (§18.5);
the engine, gate, and ledger are identical. The HITL top layer (independent audit attestation, vCISO risk
judgment, named pentest accountability) is §18.4.

---

## Q1 — Are we using the right set of OSS for accurate L1 analysis, per asset?

**Yes, and the wiring was verified (not assumed).** Each asset runs a deterministic recon → fan-out →
escalation pipeline over best-in-class OSS (CLAUDE.md §4/§5.1/§5.3); the L2 LLM never drives L1.

- **Verified correctly wired** (an audit alarm that turned out false): web `Recon()`→katana then
  `PlanFanout`→nuclei/sqlmap/dalfox; api `Recon()`→openapi-spec-ingest → `PlanFanout`→schemathesis/nuclei →
  `PlanEscalation`→kiterunner/inql. `anchorNames` is the single-target *fallback*, not the only anchors —
  blindly adding recon tools to it would double-fire.
- **Registry-tier OSS coverage extended** (deep per-language/IaC passes over the anchor scanners): gosec
  (Go SAST, #616), bandit (Python SAST, #617), KICS (deep IaC, #619), nikto (web legacy/CGI, #612), apkid
  (mobile packer/obfuscator fingerprint, #611). Each: parser unit-tested, live exec gated on the sandbox image.
- **No in-house detectors** (§13) — every detection wraps OSS; the one documented exception (api BOLA/BFLA
  authz, which has no OSS) is a differential test, not a guessed verdict.

## Q2 — Right OSS + analysis for L1.5 enrichment?

**Comprehensively extended this campaign.** The L1.5 hook chain (§11) now adds, per finding:

- **Exploit availability** (#603) — ExploitDB public-exploit refs, the patch-priority rung between EPSS and KEV.
- **CVSS base vectors** (#613) — NVD `nvd.go`, the 4th threat-intel source; surfaces `av:network`
  (network-attackable) beyond the bare score.
- **KEV-driven severity escalation** (#614) — opt-in (`TSENGINE_KEV_ESCALATE`): a sub-high finding whose CVE
  is actively exploited (CISA KEV) bumps to high per BOD 22-01; grounded, logged as a `promote`.
- **Compliance crosswalk 43 → 50 CWEs** (#620) — closed 7 unmapped common CWEs (cleartext-transit, missing-auth,
  bad-permissions, …) that were reaching the auditor with no control annotation.
- **Service-EOL flagging** (#610/#618) — an nmap-detected service below its minimum-safe version (now ~19
  daemons incl. Redis/Tomcat/MongoDB/Samba/HAProxy) bumps info→medium + upgrade guidance.
- **Dedup/corroboration verified sound** (#618) — cross_tool_merge (exact dups) + the corroborator
  (cross-tool agreement by CVE id) + UnifiedIssues are deliberately layered; no change warranted.

Threat-intel provenance: KEV/EPSS/ExploitDB/CVSS-vectors are sourced **live from OSS feeds**, pinned per scan
(§7). The CWE→control crosswalk is in-house-curated-and-grounded, cross-referenceable against **OpenCRE**
(`tsengine corpus compliance-provenance`, #621).

## Q3 — Agents where needed? Designed for long-horizon (XBOW-style) pentest?

**Yes.** The L2 agents use a ≤12-tool catalog tied to OODA (§2.6); reasoning is the LLM's, side-effects are
deterministic tools (§10).

- **Long-horizon fix (#602)** — the pentest `ModeDeep` driver was single-pass per finding; now
  `OpenEndedDriverIterative` runs a bounded observe→propose→validate→**refine** loop
  (`TSENGINE_DEEP_MAX_ATTEMPTS`): when a benign-PoC predicate fails, the failed predicates are threaded back
  so the D-agent proposes a *different* approach next attempt — the XBOW long-horizon pattern. The LLM only
  *proposes*; a deterministic predicate + the RoE guard dispose, so it can never upgrade a finding by itself
  (no LLM false positives, even across attempts).
- Agents are productized (pentest engagements, cloud-investigate); verified not orphaned.

## OSINT — external exposure (more than CVE collection; dark web?). At par with competitors?

**Now at parity for the high-signal sources** (vs SpiderFoot/GitGuardian/HudsonRock):

- **Placement**: OSINT is L1.5 + its own `/osint` UX — both, correctly.
- **Dark-web** (#604) — `osint::stealer-log`: an infostealer-harvested corporate credential (RedLine/Vidar/…),
  critical w/ plaintext password, GDPR Art. 33/34. The highest-severity OSINT signal; competitors lead here and
  we now match.
- **Continuous** (#605) — `runner.syncOSINT` runs crt.sh every monitoring pass → a newly-exposed host becomes
  an incident (the EASM "new exposure → alert" promise).
- **Public-repo secret leak** (#627) — `internal/osint/github.go`: the org's secrets leaked in *third-party*
  public repos (a former employee's dotfiles), distinct from the repository asset's own-repo scanning; reuses
  the onboarded GitHub token (no new credential), gated + best-effort.
- Honest gate: Shodan/HIBP keyed collectors are the credential-gated subset.

## Cloud engineer — is it like a cloud security engineer? Depth + coverage?

**Depth materially deepened this campaign; coverage gaps stated honestly.**

- **Effective-permission trio completed** — `cloudiam` (AWS) + `gcpiam` (GCP hierarchy-inherited bindings, #607)
  + `azureiam` (Azure RBAC Actions/NotActions + deny-assignments, #609). All three feed
  `cloudgraph.PruneUnauthorized` with identical conservatism: drop an over-approximated attack-path edge only
  on a *definitive* deny; any uncertainty keeps the edge (§10). Multi-cloud attack-path reasoning is now
  symmetric.
- **Service-coupling attack paths** (#606) — `EdgeTriggers` (API-Gateway/ALB/EventBridge → Lambda), so
  internet→apigw→fn→role→data is discoverable.
- **In-UI investigation** (#608) — `/cloud-engineer` "Run an investigation" panel.
- **Honest gates**: live Kubernetes-cluster posture (RBAC/NetworkPolicy) needs a `kubernetes` asset type
  (an ADR-level decision) + a kubeconfig; DSPM auto-classification needs a Macie/DLP connector; EC2-AMI scan
  needs sandbox snapshot-mount. K8s *manifest* scanning is already covered (checkov + kics).

## Surfacing — the enrichments reach the compliance/vCISO audience

The recent engine work is visible everywhere the consultant/auditor looks: threat-intel (CVSS vector / EPSS /
KEV / public-exploit) in the **VAPT report** (#622), the **issues triage list** (#623/#624), and the
**finding detail** panel (#625); control-mapping **provenance** on the **compliance page** (#626).

---

## What remains — gated on a decision, not on engineering

These need a product/credential/infra call, not more autonomous work:

| Item | Gate |
|---|---|
| Live Kubernetes-cluster posture (RBAC/NetworkPolicy/workload) | A `kubernetes` asset type (ADR) + kubeconfig |
| DSPM real data-classification (vs metadata-only) | A Macie / Cloud-DLP connector credential |
| Live OSINT keyed collectors (Shodan, HIBP) | Their API keys |
| Per-asset *live* benchmark numbers | A deployed sandbox image + targets |
| OpenCRE-backed % stat in the UI | A reliable out-of-band OpenCRE fetch (the `compliance-provenance` cron) |
