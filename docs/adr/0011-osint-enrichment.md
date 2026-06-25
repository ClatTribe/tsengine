# ADR 0011 — OSINT enrichment (external attacker's-eye view) on the one-platform graph

## Status
Accepted — core + ingest API + `/osint` UX + CLI + exposed-host→asset pivot + a LIVE KEYLESS Certificate-Transparency collector (`POST /v1/osint/scan`, no key/sandbox) all shipped. The KEYED collectors (Shodan/HIBP) remain the gated subset.

## Context
The one-platform strategy (CLAUDE.md §18.1 `crossdetect`) correlates findings from code, cloud,
identity, SaaS, and asset scans into one issue graph + one compliance posture. It had **threat-intel
feeds** (CISA KEV + FIRST.org EPSS, §7) and per-asset **passive recon** (subfinder/amass/crt.sh/dnstwist
on a `domain` scan) — but **no continuous, org-level OSINT layer**: the attacker's-eye view of the
company's *external* footprint. You can't scan what you don't know is exposed, and an auditor /
founder wants "are we leaking credentials, secrets, or data; is there a phishing look-alike; is there
forgotten internet-exposed infra?" answered continuously.

`taranis-ai` (the horizon-scanning / advisory-aggregation OSS the user surfaced) is one slice of this
(news/advisory monitoring). The broader OSINT space is covered by **theHarvester** (emails/subdomains/
hosts from public sources), **SpiderFoot** (200+ exposure/leak/breach modules), **dnstwist** (typosquat),
and breach feeds (**HaveIBeenPwned**-class).

## Decision
Add OSINT as an **enrichment source that feeds the existing graph**, via the same proven pattern as
SaaS-posture / identity-events (§13.1): a deterministic, LLM-free, offline-tested core that NORMALIZES
OSINT-tool output into the engine's `Finding` shape — never an in-house detector (§13). The OSINT tool
that observed each signal stays the source of truth; the core only classifies + maps to compliance (§10).

### Signals → grounded findings (`internal/osint.Assess`)
| Rule | Source OSS | Severity | Compliance (examples) | Cross-feed |
|---|---|---|---|---|
| `osint::breached-credential` | HIBP/Dehashed | high | GDPR 33/34, SOC2 CC6.1/CC7.3, PCI 8.3.1 | + identity MFA-gap ⇒ confirmed ATO path |
| `osint::leaked-secret` | trufflehog/gitleaks (public) | high→critical (validated) | SOC2 CC6.1, PCI 3.5.1, CWE-798 | rotate; audit |
| `osint::exposed-host` | theHarvester/Shodan/crt.sh | medium→high (risky svc) | SOC2 CC6.6/CC7.1, CIS 1.1/12.4 | **child-asset pivot** → web/ip scan |
| `osint::typosquat-domain` | dnstwist | low→medium (mail-capable) | NIST PR.AT-01, ISO A.5.7 | brand/anti-phishing |
| `osint::data-exposure` | SpiderFoot | high | GDPR 32/33, CCPA §1798.150 | breach-notification duty |
| `osint::advisory` | taranis-ai/NVD | by advisory (pattern_match) | SOC2 CC7.1, NIST ID.RA-02 | stack-relevant awareness |

### Integration (one-platform)
- Each signal → `Finding{tool:"osint", …, Compliance:…}` → `Store.PutFinding` → **UnifiedIssues**
  (corroborate/dedupe), **crossdetect.Correlate** (an `osint::exposed-host` or breached credential
  bridges to an internal finding via the shared host/email entity), **grc.Apply** (compliance posture),
  and `detect.OpenFor` (incident). Same wiring as the identity/SaaS ingest.
- **Detection lift:** OSINT discovers external surface the internal scanners can't see; exposed hosts
  become child-asset pivots that the engine then actively scans.
- **Compliance lift:** external exposure (breaches, leaks, public data) answers the data-protection
  control families (GDPR breach, SOC2 CC6/CC7, PCI) an auditor asks about.

### Honesty / grounding
A clean external footprint yields zero findings. Verified breaches/leaks/exposures are facts →
`verified`; advisories are awareness signals → `pattern_match`. Every finding cites its OSINT source in
`raw_output`. The **live collectors** (theHarvester/SpiderFoot in the sandbox, HIBP/Shodan APIs) are the
credential-gated half — most OSINT sources need a key — so the **posted-snapshot ingest works today with
no external creds**, exactly like the SaaS-posture path.

## Phases
0. **Core** (this ADR): `internal/osint.Assess(Snapshot) → []Finding`, deterministic + tested. ✅
1. **Ingest API**: `POST /v1/osint/ingest` → assess → store + GRC.Apply + OpenFor (no creds). + UX page
   `/osint` (External exposure) + a "Run OSINT" / connect option; marketing mention.
2. **Live collectors** (gated): theHarvester + dnstwist in the sandbox; HIBP/Shodan API connectors;
   taranis-ai advisory feed. Each honestly gated on its key/connector.
3. **Scheduler + pivot**: continuous OSINT pass in `runner.RescanTenant`; `osint::exposed-host` →
   `Scan.ChildAssets` so discovered surface is actively scanned.
