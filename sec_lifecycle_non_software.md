# Security Lifecycle Requirements for Non-Software Companies
### Goal: *"Run a secure organization"*

> **Companion to the tsengine roadmap.** tsengine encodes a *software-company*
> security lifecycle — **"build secure"**: shift-left SAST/SCA/secrets, a CI gate, and
> validation of exploitable code paths, all premised on a codebase you own and a
> pipeline you control. This document specifies the **different** lifecycle a
> *non-software* organization needs — **"run secure"** — where security is a property
> of how you *operate*, not of a product you *ship*.
>
> A non-software company (hospital, law firm, manufacturer, retailer, logistics, utility,
> professional-services or buy-not-build finance firm) **consumes** software. It usually
> cannot fix a root-cause flaw in a vendor's code; it mitigates through configuration,
> identity, segmentation, monitoring, contracts, and people. Its lifecycle is therefore
> an **operational governance loop**, governed by **NIST CSF 2.0** (Govern → Identify →
> Protect → Detect → Respond → Recover) plus a recurring **Assure/Validate** proof loop.

---

## 0. How to read this document

* **Requirement keywords** follow RFC 2119: **MUST** (mandatory), **SHOULD** (strongly
  recommended; deviations require documented risk acceptance), **MAY** (optional).
* **Each requirement** carries: an **ID**, a **statement**, a one-line **rationale**, an
  **acceptance / evidence** criterion (how an auditor proves it is met), an **owner**
  role, and a **maturity tier**.
* **Maturity tiers** sequence adoption — an org should reach all **T1** before chasing T3:
  * **T1 — Foundational** *(survive: stop the common breach)*
  * **T2 — Managed** *(measured, repeatable, owned)*
  * **T3 — Optimized** *(continuous, automated, validated)*
* **Scope.** Requirements cover the enterprise IT/operational estate the organization
  *operates*: identities, endpoints, networks, SaaS, cloud tenants, data, vendors,
  facilities, people, and (where present) OT/IoT. They do **not** assume an in-house
  SDLC; §8 covers what changes if the org also builds software.
* **Crosswalk.** §11 maps every requirement to NIST CSF 2.0, ISO/IEC 27001:2022, and
  CIS Controls v8 so this spec drops into an existing compliance program.

### The lifecycle at a glance

```
                 ┌──────────────── GOVERN (continuous) ────────────────┐
                 │  leadership · risk · policy · compliance · culture   │
                 └──────────────────────────────────────────────────────┘
   IDENTIFY  ─────►  PROTECT  ─────►  DETECT  ─────►  RESPOND  ─────►  RECOVER
   know what      reduce the       see the         contain &        restore &
   you have,      attack surface   attack          eradicate        learn
   own, & trust   & the human                                          │
        ▲                                                              │
        └──────────────── ASSURE / VALIDATE (recurring proof) ─────────┘
            pen-test · phishing sim · tabletop · audit · attestation
```

---

## 1. GOVERN — leadership, risk, policy, culture *(the continuous wrapper)*

> Without governance the other phases are uncoordinated spend. For a non-software
> company this is the heaviest phase, because security is run as a **program**, not a
> pipeline.

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **GOV-1** | The organization **MUST** assign a single accountable security leader (CISO / vCISO / Head of Security) with a defined mandate and a direct line to executive leadership/board. | Org chart + charter naming the role; ≥quarterly security report to the board/exec. | Exec / Board | T1 |
| **GOV-2** | The organization **MUST** maintain a **risk management program**: a living risk register, a stated risk appetite, and a documented risk-assessment cadence (≥annual, and on major change). | Risk register with owners, scores, treatment decisions; signed risk-acceptance records. | CISO | T1 |
| **GOV-3** | The organization **MUST** maintain an approved **policy framework** covering at minimum: information security, acceptable use, access control, data classification & retention, incident response, business continuity, and third-party/vendor security. | Version-controlled policies, dated, exec-approved, reviewed ≥annually; staff attestation. | CISO / Legal | T1 |
| **GOV-4** | The organization **MUST** determine and document its **regulatory & contractual compliance scope** (e.g. GDPR/CCPA, HIPAA, PCI-DSS, SOC 2, ISO 27001, sector rules) and map obligations to controls. | Compliance applicability statement; obligation-to-control matrix. | CISO / Compliance | T1 |
| **GOV-5** | Security **MUST** have a dedicated, ring-fenced **budget and resourcing plan** proportional to assessed risk. | Approved annual security budget line; headcount/MSSP plan. | Exec | T2 |
| **GOV-6** | The organization **MUST** run a recurring **security-awareness & culture program** for all staff (onboarding + ≥annual refresh), because people are the primary attack surface. | LMS completion records ≥95%; role-based modules for high-risk staff (finance, exec, IT). | CISO / HR | T1 |
| **GOV-7** | Security responsibilities **SHOULD** be expressed as a **RACI** across business owners, IT, and security, so no control is unowned. | Published RACI mapped to this spec's requirement IDs. | CISO | T2 |
| **GOV-8** | The organization **SHOULD** adopt a recognized control framework (NIST CSF 2.0, ISO 27001, or CIS Controls v8) as the **single source of truth** and measure against it. | Documented framework selection + current maturity baseline. | CISO | T2 |

---

## 2. IDENTIFY — know what you have, own, and trust

> The most common root cause of breaches at non-software orgs is *"we didn't know that
> asset/identity/vendor existed or was exposed."* You cannot protect what you have not
> inventoried.

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **IDN-1** | The organization **MUST** maintain an authoritative, regularly reconciled **asset inventory** spanning hardware, servers, end-user devices, mobile, software, **SaaS applications**, cloud tenants, network gear, and **OT/IoT** devices. | Inventory system (CMDB/ITAM) with last-seen timestamps; reconciliation report ≥monthly; documented coverage of unmanaged/shadow assets. | IT Ops | T1 |
| **IDN-2** | The organization **MUST** maintain a **data inventory & classification**: what regulated/sensitive data it holds, where it lives, how it flows, and who owns it. | Data map / RoPA; classification labels (e.g. Public/Internal/Confidential/Restricted); data-owner assignments. | Data Protection Officer | T1 |
| **IDN-3** | The organization **MUST** continuously discover its **external attack surface** — owned domains, subdomains, public IP ranges, internet-exposed services, certificates, and SaaS tenants — and flag unknown/unsanctioned exposure. | EASM scan output reviewed ≥monthly (≥weekly at T3); exposure register with owners. *(Automatable — see §9; this is where a tool like tsengine's `domain`/`ip_address`/`cloud_account` scanning + grounded validation applies.)* | Security Ops | T2 |
| **IDN-4** | The organization **MUST** maintain a **third-party / vendor inventory** risk-tiered by data access and business criticality (Third-Party Risk Management). | Vendor register with tier, data-access scope, contract & DPA status, last assessment date. | Procurement / TPRM | T1 |
| **IDN-5** | The organization **MUST** maintain an **identity inventory** covering workforce, privileged, service, and machine/non-human identities, including those in SaaS and cloud. | Identity source-of-truth (IdP) report; privileged-account register; orphaned-account review. | IAM Lead | T2 |
| **IDN-6** | The organization **SHOULD** conduct a **Business Impact Analysis** identifying crown-jewel data, systems, and processes and their tolerable downtime/loss. | BIA document with RTO/RPO per critical process; crown-jewel list. | Business Owners | T2 |

---

## 3. PROTECT — reduce the attack surface (technical + human)

> Protection at a non-software company is **identity-first** and **people-heavy**: you
> mostly can't change vendor code, so you control *who can reach what*, *from where*, and
> *who can be tricked*.

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **PRO-1** | **Phishing-resistant or strong MFA MUST be enforced** on all user, remote-access, privileged, and internet-facing accounts; **SSO SHOULD** consolidate authentication. | IdP policy showing MFA coverage ≥99% of accounts; exception register. | IAM Lead | T1 |
| **PRO-2** | Access **MUST** follow **least privilege** with a **Joiner–Mover–Leaver** process and **periodic access reviews** (≥quarterly for privileged, ≥annual for standard). | Access-review attestations; deprovisioning SLA evidence (leavers disabled ≤24h). | IAM Lead | T1 |
| **PRO-3** | Privileged access **MUST** be governed by **PAM** — vaulted credentials, just-in-time elevation, session logging — for admins of critical systems. | PAM tool coverage report; standing-admin count trending down. | IAM Lead | T2 |
| **PRO-4** | All endpoints and servers **MUST** run managed **EDR**, full-disk **encryption**, and a hardened **configuration baseline** (e.g. CIS Benchmarks); mobile via MDM. | EDR/MDM enrollment ≥98%; encryption compliance report; baseline scan results. | IT Ops | T1 |
| **PRO-5** | A **vulnerability & patch-management** program **MUST** remediate known vulnerabilities on operated systems within severity-based SLAs (e.g. Critical ≤7d external-facing). | Patch-compliance dashboard; SLA adherence metrics; exception/risk-acceptance log. | IT Ops | T1 |
| **PRO-6** | The network **MUST** be **segmented** to isolate user, server, guest, management, and especially **OT/IoT** zones; remote access **MUST** be brokered (ZTNA/VPN + MFA), not flat. | Network diagram with segmentation/ACLs; OT isolation evidence; no flat /16. | Network/Security | T2 |
| **PRO-7** | **Email & domain security MUST** be enforced: anti-phishing/malware filtering, and **SPF + DKIM + DMARC (p=reject)** on all sending domains. | Mail-gateway config; DMARC aggregate reports at enforcement. | IT Ops | T1 |
| **PRO-8** | **Data protection controls MUST** apply to classified data: encryption in transit and at rest, key management, and **DLP** for the most sensitive categories. | Encryption inventory; DLP policy + alert review; KMS/HSM evidence. | Security / DPO | T2 |
| **PRO-9** | SaaS estates (M365/Google Workspace, CRM, file-sharing) **MUST** be hardened and continuously monitored for misconfiguration and risky OAuth grants (**SSPM/CASB**). | SSPM posture score; OAuth-app review; external-sharing controls evidence. | Security Ops | T2 |
| **PRO-10** | **Third-party risk MUST** be controlled before and during engagement: security due diligence proportional to tier, contractual security/DPA clauses, least-privilege vendor access, and offboarding. | Pre-onboarding assessment records; signed clauses; vendor-access reviews; continuous monitoring for Tier-1 vendors. | TPRM | T2 |
| **PRO-11** | **Backups MUST** be protected as a control surface — immutable/offline copy, encrypted, access-restricted — to survive ransomware (see also RCV-1). | Immutable-backup configuration; backup-admin separation of duties. | IT Ops | T1 |
| **PRO-12** | **Physical & facilities security MUST** protect sites housing systems/data: access control, visitor management, and environmental controls; OT sites add safety-system protection. | Badge-system logs; visitor records; data-center/closet access list. | Facilities | T2 |
| **PRO-13** | A recurring **security-awareness & phishing-simulation** program **MUST** train staff and measure susceptibility, with targeted follow-up for repeat clickers. | Simulation campaign results (click & report rates trending favorably); remedial training records. | CISO / HR | T1 |

---

## 4. DETECT — see the attack

> For a non-software company, **Detect is the center of gravity** (the SOC / "operate"
> layer), because prevention of every vendor/identity/human weakness is impossible.

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **DET-1** | Security-relevant **logs MUST** be centrally collected and retained (identity, endpoint/EDR, network, SaaS, cloud, email) per a defined retention policy. | SIEM/log-platform with documented source coverage & retention; gap analysis vs IDN-1. | Security Ops | T1 |
| **DET-2** | The organization **MUST** have **24×7 monitoring & triage** capability — in-house SOC or an outsourced **MDR/MSSP** — with defined alert handling. | SOC/MDR contract or roster; alert-handling runbook; coverage-hours evidence. | Security Ops | T1 |
| **DET-3** | **Detection content SHOULD** be mapped to **MITRE ATT&CK** and gaps tracked, so coverage is measured rather than assumed. | ATT&CK coverage heatmap; detection-engineering backlog. | Detection Eng | T3 |
| **DET-4** | **Threat intelligence SHOULD** feed detection and prioritization (sector ISAC, vendor feeds, CISA advisories). | TI-source list; examples of TI-driven detections/blocks. | Security Ops | T2 |
| **DET-5** | **Anomaly & insider-threat detection SHOULD** cover identity misuse, impossible travel, mass-download, and privilege misuse. | UEBA/identity-analytics alerts; insider-risk review process. | Security Ops | T3 |
| **DET-6** | Detection efficacy **SHOULD** be validated periodically via **purple-team/breach-and-attack-simulation** (links to ASR-3). | Purple-team report; detections added/tuned as a result. | Security Ops | T3 |

---

## 5. RESPOND — contain, eradicate, communicate

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **RSP-1** | An **Incident Response Plan MUST** exist with scenario **playbooks** for the highest-likelihood events (ransomware, business-email-compromise, data breach, vendor compromise, account takeover). | Approved IRP + dated playbooks; review ≥annual. | CISO | T1 |
| **RSP-2** | An **IR team with defined roles MUST** be named (incident commander, technical lead, comms, legal, executive sponsor, external forensics retainer). | RACI for incidents; on-call roster; signed IR-firm retainer. | CISO | T1 |
| **RSP-3** | The organization **MUST** define and measure **MTTD/MTTR** targets and escalation thresholds. | Metrics dashboard; incident timelines vs targets. | Security Ops | T2 |
| **RSP-4** | A **breach-notification & regulatory-reporting process MUST** track legal clocks (e.g. GDPR 72h, HIPAA, sector regulators) and customer/contractual obligations. | Notification decision tree; legal-counsel involvement; jurisdiction matrix. | Legal / DPO | T1 |
| **RSP-5** | **Response automation (SOAR) SHOULD** accelerate containment of common incidents (isolate host, disable account, block indicator). | SOAR playbooks; automated-containment evidence. | Security Ops | T3 |
| **RSP-6** | Every significant incident **MUST** trigger a **post-incident review** that feeds corrective actions back into Protect/Detect. | PIR documents with tracked action items to closure. | CISO | T2 |

---

## 6. RECOVER — restore and learn

> Ransomware turned recovery from a back-office function into an existential control.
> *Untested backups are not a recovery capability.*

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **RCV-1** | Backups **MUST** follow a resilient strategy (e.g. **3-2-1-1** with an immutable/offline copy) for all critical systems and data. | Backup policy + configuration; immutability proof; coverage vs crown-jewel list. | IT Ops | T1 |
| **RCV-2** | **Restores MUST be tested** on a defined cadence against documented **RTO/RPO**, including a full critical-system recovery rehearsal. | Restore-test logs with measured recovery times; gaps remediated. | IT Ops | T1 |
| **RCV-3** | A **Business Continuity & Disaster Recovery plan MUST** exist for critical processes, exercised ≥annually. | BCP/DR plan; exercise after-action report. | BC Manager | T2 |
| **RCV-4** | A **crisis-management & communications plan MUST** cover internal, customer, regulator, and (if needed) public messaging. | Comms templates; spokesperson designation; legal pre-review. | Comms / Legal | T2 |
| **RCV-5** | The organization **SHOULD** evaluate **cyber-insurance / risk transfer** aligned to residual risk and ensure control prerequisites are met. | Policy in force; control-attestation alignment; coverage-vs-BIA review. | CFO / CISO | T2 |

---

## 7. ASSURE / VALIDATE — prove it works (the recurring loop)

> Controls decay. This phase **independently proves** the program still holds and feeds
> findings back into the loop. It is where a non-software org *buys* offensive/validation
> capability rather than building it.

| ID | Requirement | Acceptance / evidence | Owner | Tier |
|---|---|---|---|---|
| **ASR-1** | **Independent penetration testing MUST** be performed ≥annually (and on major change) against external, internal, and identity/SaaS surfaces; findings tracked to closure. | Pen-test reports; remediation tracker; retest evidence. | CISO | T1 |
| **ASR-2** | A **phishing-simulation program MUST** run on a recurring cadence with measured, trending click/report rates (operationalizes PRO-13). | Campaign metrics over time; improvement trend. | CISO | T1 |
| **ASR-3** | **Tabletop exercises MUST** be run ≥annually for top incident scenarios, involving exec, legal, and IT/security; **red/purple-team SHOULD** follow at higher maturity. | Exercise records; action items; (T3) red-team report. | CISO | T2 |
| **ASR-4** | **Internal and independent external audits / attestations MUST** validate control operation against the chosen framework(s) (ISO 27001, SOC 2, PCI, HIPAA as applicable). | Audit reports; certificates/attestations; nonconformity closure. | Compliance | T2 |
| **ASR-5** | **Continuous control monitoring SHOULD** replace point-in-time checks where feasible (GRC tooling, posture monitoring, EASM, SSPM). | Continuous-monitoring dashboards; auto-collected evidence. | Compliance / Security Ops | T3 |
| **ASR-6** | A **security metrics & board-reporting** package **MUST** report program health and risk posture to leadership ≥quarterly (see §10). | KPI dashboard; board-pack minutes. | CISO | T2 |

---

## 8. What changes if the org *also* builds (or heavily customizes) software

Many "non-software" companies still build internal apps, integrations, low-code/RPA
automations, or customer portals. To the extent they do, the **build-secure** lifecycle
(tsengine's home turf) layers on top of the above:

* **SDLC security** — SAST/SCA/secret scanning + a **CI gate** on code they own (the
  shift-left pillar). *This is exactly tsengine's `repository`/`container_image`/`api`
  scope.*
* **Secure-by-procurement (the inverse)** — for *bought* software, push requirements onto
  the vendor (security questionnaires, SOC 2/ISO evidence, SBOM requests, DPAs) instead
  of shifting left. This is the dominant pattern and is covered by **PRO-10 / IDN-4**.
* **Low-code/RPA/citizen-dev governance** — inventory and govern automations that act
  with real identities; they are an under-managed privileged surface.

---

## 9. Tooling map — and where an offensive/validation engine fits

| Lifecycle phase | Typical tooling category | Where a validation engine (e.g. tsengine) fits |
|---|---|---|
| Identify | ITAM/CMDB, **EASM**, TPRM, IdP, data-discovery | ✅ **EASM + cloud posture**: discover `domain`/`ip_address`/`cloud_account`/exposed `web_application`, then **validate which exposures are real** and prioritize — high value |
| Protect | IdP/MFA, PAM, EDR, MDM, email security, DLP, SSPM, patch | ➖ mostly configuration products; engine confirms hardening externally |
| Detect | SIEM, MDR/SOC, XDR, UEBA, TI | ➖ the **operate** layer (blue team / AI-SOC) — the engine is a *finding source* feeding it |
| Respond | SOAR, IR retainer, case mgmt | ➖ separate |
| Recover | Backup/immutability, DR orchestration | ➖ separate |
| Assure | Pen-test, phishing-sim, **GRC/continuous monitoring**, audit | ✅ **continuous external validation** + signed, replayable evidence for auditors |

> **Read:** for a non-software company, an offensive/validation engine is **not** the
> backbone of the program — governance, identity, detection/response, and people are. It
> is a high-leverage **input** to *Identify* (EASM + grounded exposure validation) and
> *Assure* (continuous external proof), feeding the **operate (SOC)** and **GRC** layers
> that carry the weight.

---

## 10. Metrics & KPIs (minimum board-level set)

| Phase | Example KPI | Healthy direction |
|---|---|---|
| Identify | % assets in authoritative inventory; unknown internet-exposed services | ↑ coverage / ↓ unknowns |
| Protect | MFA coverage %; mean time to patch (critical); access-review completion %; phishing click rate | ↑ / ↓ / ↑ / ↓ |
| Detect | log-source coverage %; MTTD; % alerts triaged in SLA | ↑ / ↓ / ↑ |
| Respond | MTTR; % incidents with completed PIR | ↓ / ↑ |
| Recover | restore-test success %; measured RTO/RPO vs target | ↑ / meet |
| Assure | open critical pen-test findings past SLA; framework maturity score | ↓ / ↑ |

---

## 11. Compliance crosswalk (requirement → framework)

| Phase (IDs) | NIST CSF 2.0 | ISO/IEC 27001:2022 (Annex A themes) | CIS Controls v8 |
|---|---|---|---|
| GOV-1…8 | **GOVERN** (GV.*) | 5 Organizational (policies, roles, supplier, compliance) | 14, 17 (awareness, IR mgmt) |
| IDN-1…6 | **IDENTIFY** (ID.AM, ID.RA, ID.SC) | 5/8 (asset, classification, supplier) | 1, 2, 3 (asset, software, data) |
| PRO-1…13 | **PROTECT** (PR.AA, PR.DS, PR.PS, PR.IR) | 5/7/8 (access, physical, technological) | 4,5,6,7,9,10,12,13 |
| DET-1…6 | **DETECT** (DE.CM, DE.AE) | 8 (logging, monitoring) | 8, 13 (audit logs, network monitoring) |
| RSP-1…6 | **RESPOND** (RS.*) | 5 (incident management) | 17 (incident response) |
| RCV-1…5 | **RECOVER** (RC.*) | 5/8 (continuity, backup) | 11 (data recovery) |
| ASR-1…6 | cross-cutting (GV.OV, ID.RA, PR.* validation) | 5 (compliance, audit) | 18 (pen testing) |

*(Crosswalk is indicative for program design — confirm exact control IDs against current
framework releases during certification.)*

---

## 12. Implementation roadmap (phased)

**Phase A — Foundational (0–3 months): stop the common breach.**
GOV-1/2/3/4/6 · IDN-1/2/4 · PRO-1/2/4/5/7/11/13 · DET-1/2 · RSP-1/2/4 · RCV-1/2 · ASR-1/2.
*Outcome: MFA everywhere, EDR + immutable backups, asset/data/vendor inventory, a SOC/MDR
watching, an IR plan, an annual pen test, and trained staff. This alone removes the
majority of real-world incident root causes.*

**Phase B — Managed (3–9 months): measured & owned.**
GOV-5/7/8 · IDN-3/5/6 · PRO-3/6/8/9/10/12 · DET-4 · RSP-3/6 · RCV-3/4/5 · ASR-3/4/6.
*Outcome: PAM, segmentation, EASM + SSPM, formal TPRM, BCP/DR exercised, metrics to the
board, framework certification underway.*

**Phase C — Optimized (9–18 months): continuous & validated.**
DET-3/5/6 · RSP-5 · ASR-5 · plus §8 if building software.
*Outcome: ATT&CK-mapped detection, SOAR-driven containment, continuous control monitoring,
purple-teaming — a program that proves itself rather than asserting compliance.*

---

### One-line summary

> For a software company, security **is** the SDLC. For a non-software company, security
> is an **operational governance loop** — *know what you have and trust* (Identify),
> *shrink the identity/human/vendor surface* (Protect), *watch* (Detect), *contain*
> (Respond), *restore* (Recover), and *independently prove it* (Assure) — all wrapped in
> Governance. Technical scanning is one valuable input; the program is carried by people,
> process, identity, detection/response, and compliance.
