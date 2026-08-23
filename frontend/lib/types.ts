// Mirrors the Go /v1 JSON contracts (pkg/types + pkg/platform). Only the fields the UI uses.

// AIAnalysis — a persisted run of the AI Security Engineer (Triage / Investigate / Cloud), so a run
// survives navigation. Mirrors pkg/platform.AIAnalysis.
export interface AIReport {
  title: string;
  severity?: string;
  body?: string;
}
export interface AIAnalysis {
  id: string;
  kind: string; // "triage" | "investigate" | "cloud"
  scope?: string;
  title?: string;
  summary: string;
  recommends?: string; // "what to do next" — the fix narrative
  methodology?: string;
  reports?: AIReport[];
  model?: string;
  iterations?: number;
  cost_usd?: number;
  created_at: string;
}

// ComplianceFixes — the compliance→remediation bridge: which control gaps are fixable now (findings that
// already have a queued remediation action). Mirrors platformapi.ComplianceFixes.
export interface ControlFix {
  control_id: string;
  finding_count: number;
  fixable_count: number;
  pending_count: number;
  applied_count: number;
  action_ids?: string[];
  pending_action?: string;
}
export interface ComplianceFixes {
  framework: string;
  gap_controls: number;
  fixable_gaps: number;
  pending_fixes: number;
  controls?: ControlFix[];
}

export interface Finding {
  id: string;
  rule_id: string;
  tool: string;
  severity: string;
  title: string;
  description?: string;
  endpoint?: string;
  cwe?: string[];
  mitre_techniques?: string[];
  verification_status?: string;
  confidence?: number;
  // The rule ids of the OTHER findings that independently agreed — the evidence behind the word
  // "corroborated" and the confidence number beside it. The corroborator hook only counts findings
  // from DISTINCT tools on the same surface, since two hits from one scanner are not independent.
  // §10 is "every recorded issue cites tool evidence"; the citation was computed and reached the L2
  // digest and the zero-JS console, and this page showed the verdict without it.
  corroborated_by?: string[];
  // How reachable the surface is (a login form outranks a robots.txt entry). Structurally identical
  // to exploitability, which this page has always rendered with its reason — showing one and not the
  // other left the reader with half of the ranking the engine actually computed.
  surface_priority?: { score?: number; reason?: string };
  // What the TOOL itself said, and how it was invoked. Stored since Phase 0 and never shown until
  // now — a security engineer verifies a finding by reading the scanner's own output, not our
  // summary of it, and they cannot reproduce a result whose arguments they cannot see.
  raw_output?: unknown;
  tool_args?: Record<string, string>;
  // Provenance. "human_reinstated" means a person put this back over the L1.5 filter's dismissal,
  // which a reader must be able to tell apart from a finding the AI approved.
  discovery_method?: { primary?: string; replay_of?: string };
  // blast_radius: read-time impact sizing — does this finding chain to a crown jewel? (mirrors incidents)
  blast_radius?: { reaches_crown_jewel: boolean; crown_jewel_type?: string; hops?: number };
  // Our OWN exploitability assessment, and the reason for it. The L1.5 hook can PROMOTE a finding's
  // severity upward on this basis — a critical-class CWE rated below high becomes high — so the
  // severity a reader sees is sometimes ours rather than the scanner's, and nothing said so. §2.5
  // requires the L1 audience be able to audit and override what the AI decided; they cannot audit
  // reasoning that is not shown.
  exploitability?: { score?: number; reason?: string };
  threat_intel?: {
    cvss?: number;
    cvss_vector?: string; // CVSS base vector (NVD) — attack-vector detail
    kev?: { listed?: boolean; date_added?: string } | null; // CISA KEV (actively exploited)
    epss?: { score?: number; percentile?: number } | null; // FIRST.org exploit probability
    advisories?: string[];
    exploits?: string[]; // public exploit/PoC refs (ExploitDB/Metasploit)
    // Metasploit's own reliability rank for the best module targeting this CVE: excellent | great |
    // good | normal | average | low | manual.
    //
    // It exists because "a public exploit exists" collapses two very different situations. A module
    // ranked excellent never crashes the service and runs use/set/run — an operator who could not
    // write the exploit can run it tonight. One ranked manual needs hand-holding and may not work at
    // all. The corpus discriminates in practice rather than sitting at the top (live: 1,383
    // excellent against 78 manual), and it reached the L2 digest while the human triaging the
    // finding saw the same sentence either way.
    weapon_rank?: string;
    // CISA's own decision assessment (Vulnrichment/ADP), recorded verbatim. Automatable is the only
    // signal here that separates a vulnerability exploited by hand against one target from one that
    // can be driven across an estate — KEV is binary and covers ~1,700 CVEs, EPSS is a probability,
    // and neither answers it. Surfaced to the READER as well as the digest: weapon_rank reached the
    // L2 agent for months while the human triaging the finding saw nothing, and repeating that with
    // a second signal would be the same mistake twice.
    ssvc?: { exploitation?: string; automatable?: string; technical_impact?: string };
  } | null;
  // DerivedFrom are the finding ids a DERIVED finding rests on — one produced by JOINING other
  // findings rather than by a tool observing something directly (a cross-surface chain: this leaked
  // key reaches that cloud role). §10 requires every recorded issue to cite its evidence, and for a
  // derived finding the evidence IS these ids. Its Go doc says that without them it would be "an
  // assertion with nothing behind it" — which is exactly what the page showed before this.
  derived_from?: string[];
  compliance?: Record<string, string[]> | null;
  // Cloud-to-Code: a runtime cloud finding traced back to the IaC resource +
  // file:line that provisioned it. Present only on cloud findings the
  // correlator confidently linked to source; absent otherwise.
  code_provenance?: CodeProvenance | null;
}

export interface CodeProvenance {
  file: string;
  line: number;
  iac_resource: string;
  matched_on: string;
  match_basis: string;
  confidence: string; // "high" | "medium"
}

// Cross-surface attack path (GET /v1/attack-paths) — a finding on one surface
// that bridges, via a concrete shared identifier, to a crown jewel on another.
export interface AttackStep {
  asset_type: string;
  asset_target: string;
  finding_id: string;
  title: string;
  severity: string;
  verified?: boolean;
  via_entity?: string; // the shared identifier that leads to the NEXT step
  crown_jewel?: boolean;
}

export interface AttackPath {
  severity: string;
  steps: AttackStep[];
}

export interface AttackPaths {
  attack_paths: AttackPath[];
  count: number;
  // The basis the correlation ran over. Zero paths is only good news if there was something to
  // correlate — a chain is built FROM findings, so an unscanned estate yields zero just like a
  // secure one. Optional so an older API response still parses.
  correlated_findings?: number;
  assets_considered?: number;
}

// Unified issue (GET /v1/issues) — the same weakness reported by one or more
// scanners across surfaces, collapsed into one row ("one issue, many signals").
// What this tenant's own judgements add up to. Both axes were collected and neither was ever shown
// back: the verdict reached the eval suite, the evidence axis became prose inside a case's reason
// string, and no page read any of it — so someone who answered "no, you did not show me why" had no
// sign it landed anywhere. evidence_insufficient is a defect in OUR write-up rather than in the
// finding, which is what makes weakest_explanations the list to act on.
export interface FeedbackSummary {
  total: number;
  real: number;
  false_positive: number;
  unclear: number; // first-class: "I could not understand this" is an answer, not an absence of one
  evidence_sufficient: number;
  evidence_insufficient: number;
  evidence_unanswered: number; // counted, so a low insufficient count is not mistaken for approval
  weakest_explanations?: { issue_key: string; count: number }[];
}

export interface Issue {
  key: string;
  title: string;
  severity: string;
  cve?: string;
  endpoint?: string;
  tools: string[];
  count: number;
  confirmed: boolean; // ≥2 independent scanners agree
  finding_ids: string[];
  attacked?: boolean; // endpoint observed under attack in production (runtime signal)
  // Data-tier prioritisation: the list is RE-SORTED by risk_rank (severity x tier), so a Medium on a
  // customer-data asset can outrank a Medium on a low-sensitivity one. Without showing the tier, that
  // reordering is invisible reasoning — two Mediums appear in an order the reader cannot account for,
  // and the product has the answer.
  //
  // Both are omitempty and zero until an owner tiers the asset AND the issue is attributable to it,
  // so the chip appears only where the tier actually moved something.
  data_tier?: number; // 1 = customer data, 2 = standard, 3 = low sensitivity
  risk_rank?: number;
  attack_count?: number;
  // Live-exploitable fusion (the ACSP "active/reachable/exploitable" lens): genuinely live, not
  // just present — under attack, OR internet-exposed on an attack path, OR exposed+serious+corroborated.
  live?: boolean;
  live_reason?: string;
  exposed?: boolean;
  in_attack_path?: boolean;
  // L1.5 threat-intel enrichment (aggregated across the issue's findings): the patch-priority signals.
  kev?: boolean; // a CVE in the group is on CISA KEV — actively exploited in the wild (patch now)
  epss?: number; // FIRST.org exploit probability 0..1 (worst across the group)
  cvss?: number; // worst CVSS base score across the group
  cvss_vector?: string; // CVSS base vector (NVD) — attack-vector detail
  public_exploit?: boolean; // a public exploit/PoC exists (ExploitDB/Metasploit)
}

// Explanation is the plain-English answer for a reader with no security background: what broke, why it
// matters HERE, what to do, how soon. Produced deterministically by the server (internal/explain), so
// it is present with the AI turned OFF — that is what makes the deterministic tier readable rather
// than raw.
export interface Explanation {
  headline: string;
  what: string;
  why: string;
  fix: string;
  urgency: "now" | "this_week" | "this_month" | "whenever";
  urgency_label: string;
  // because lists the FACTS behind the urgency, so a reader can check our reasoning instead of
  // trusting a label. This is the anti-"everything is critical" mechanism; render it, do not drop it.
  because?: string[];
  technical: { rule_id?: string; tool?: string; cwe?: string[]; severity?: string; endpoint?: string };
}

export interface IssuesResponse {
  issues: Issue[];
  count: number;
  raw_findings: number;
  confirmed: number;
  ignored?: number;
  excluded?: number; // findings dropped by custom exclusion rules
  attacked?: number; // issues observed under attack in production
  live?: number; // issues that are genuinely live-exploitable (the ACSP fusion)
  // explanations is keyed by issue key. Optional so an older server (or an empty estate) renders the
  // raw title rather than a blank row.
  explanations?: Record<string, Explanation>;
}

// A custom noise-filter rule (Aikido "custom rules": exclude paths/packages/conditions).
export interface ExclusionRule {
  id: string;
  tenant_id: string;
  field: string; // rule_id | package | path | cve | any
  pattern: string;
  reason?: string;
  note?: string;
  by?: string;
  at?: string;
}

// Pentest engagement (GET/POST /v1/pentest) — the productized AI-pentest lifecycle.
export interface RulesOfEngagement {
  authorized_targets: string[];
  out_of_scope?: string[];
  max_requests: number;
  rate_per_minute?: number;
  allow_active?: boolean;
  authorized_by?: string;
  consent?: string; // explicit recorded consent statement (required for active mode)
}

// Signoff is a named human's review attestation on the pentest report (named accountability).
export interface Signoff {
  signer: string;
  role?: string;
  statement?: string;
  signed_at: string;
  ledger_ref?: string;
  capacity?: string; // who the signer works for: internal | msp | managed
  firm?: string;
}

export interface PentestEngagement {
  id: string;
  tenant_id: string;
  name: string;
  mode: string; // "passive" | "active"
  status: string; // draft|authorized|running|reporting|complete|retesting|halted
  rules_of_engagement: RulesOfEngagement;
  findings?: Finding[] | null;
  requests_used: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  signoff?: Signoff | null; // named human sign-off on the report (the HITL accountability)
  schedule?: { cadence: string; next_run_at?: string } | null; // recurring re-test cadence (safe passive re-verify)
  // What the agent TRIED, including what the Rules of Engagement refused to let it run. Without
  // this a reader cannot tell "tested and held" from "never tested" — and a blocked probe means
  // that test did not happen, however clean the report looks.
  attempts?: PentestAttempt[] | null;
  attempts_truncated?: number;
}

export interface PentestAttempt {
  target: string;
  method?: string;
  active?: boolean;   // an exploitation attempt rather than a benign probe
  allowed: boolean;   // the Rules-of-Engagement verdict
  reason?: string;    // why it was refused, or that it was within the rules
  proven?: boolean;   // allowed && !proven = tried and could not be demonstrated
  at: string;
}

export interface PentestStats {
  engagements: number;
  active_engagements: number;
  completed_runs: number;
  total_findings: number;
  high_plus: number;
  exploitation_proven: number;
  high_plus_proven: number;
  verified_rate: number; // 0..1
  high_plus_found: boolean;
  needs_review: number; // high+ findings actively probed but not auto-proven → manual HITL sign-off
  // assessed_runs is the subset of completed_runs that actually examined something. A run reaching
  // "complete" is a statement about the workflow, not about the target.
  assessed_runs: number;
  // caveat is set when the numbers must not be read as a result — e.g. a completed run that sent no
  // probes and saw no findings, where "0 findings" says nothing about the target. Empty otherwise,
  // deliberately: a disclaimer on every scorecard is one nobody reads.
  caveat?: string;
}

// Pre-flight readiness for an engagement (GET /v1/pentest/{id}/readiness) — surfaces, before a
// run, what still blocks an active/deep exploitation: per-target ownership, recorded consent, and
// whether an LLM is configured to actually discover vulns.
export interface TargetReadiness {
  target: string;
  owned: boolean;
  method?: string; // dns_txt | well_known | connection | verified
  asset_id?: string;
  needs_challenge: boolean;
  note?: string;
}
export interface AIReadiness {
  configured: boolean;
  source: string; // tenant_key | operator | none
  discovery_will_run: boolean;
  note: string;
}
export interface PentestReadiness {
  engagement_id: string;
  mode: string;
  ready: boolean;
  requires_consent: boolean;
  consent_present: boolean;
  ai: AIReadiness;
  scope: TargetReadiness[];
  blockers: string[];
}

// Ownership challenge (POST /v1/assets/{id}/ownership/challenge) — the token + publishing
// instructions the customer follows to PROVE they control a standalone target.
export interface OwnershipChallenge {
  token: string;
  host: string;
  dns_name: string;
  dns_value: string;
  file_url: string;
  file_content: string;
}
export interface OwnershipResult {
  verified: boolean;
  method?: string; // dns | file | ""
}

export interface Action {
  id: string;
  tenant_id: string;
  finding_id: string;
  finding_ids?: string[]; // a bulk action resolves >1 finding (one PR, many alerts)
  connection_id?: string;
  kind: string;
  tier: number;
  status: string;
  title?: string;
  payload?: Record<string, unknown>;
  finding_keys?: string[];
  // The named human who passed this through the HITL gate. The central invariant is that the only
  // write path is reached AFTER a human decides (§18.2 inv. 3) and that every decision is signed
  // into the ledger (inv. 4) — so WHO decided is the accountability record, not a nicety. It was
  // stored on the action and signed, and no screen declared it, so an applied change to a customer's
  // cloud showed no sign of who authorised it.
  approver?: string;
  verification?: FixVerification; // set once an applied fix is re-tested (KF#4)
  // Why the last apply attempt failed, redacted server-side. A failed action deliberately stays at
  // "approved" so it is not lost, which also makes it look identical to one merely waiting — this is
  // what tells the two apart.
  delivery_error?: string;
  // A KNOWN reason this action could not be applied if approved right now (read-time preflight,
  // never persisted). Shown BEFORE the decision so nobody approves a fix that cannot land. Absent
  // means "no known blocker", not "guaranteed to work".
  apply_blocked?: string;
  /**
   * What this tenant's own history says about whether THIS kind of fix has actually closed THIS kind
   * of finding before (ADR 0025 F2). Read-time, never persisted. ABSENT means "not enough history" —
   * never "this will work", and never render a zeroed record, which reads as a fix that never works.
   */
  fix_efficacy?: FixEfficacy;
  created_at?: string;
  decided_at?: string; // when the approve/reject verdict landed
  // diff is the unified diff this action would apply, rendered for a human to READ. Without it a
  // reviewer approving a code change is signing for something they cannot see.
  diff?: string;
  // The review thread: feedback is what the reviewer asked to change; supersedes points at the
  // proposal this one replaces. Set when status is "changes_requested" / on a re-proposal.
  feedback?: string;
  reviewed_by?: string;
  reviewed_at?: string;
  supersedes?: string;
}

// FixVerification — did an applied remediation actually close the finding? "fixed" only when the
// vuln is provably gone from a fresh scan; "still_present" when the fix didn't work (reopen).
export interface FixVerification {
  status: "fixed" | "still_present";
  method: string;
  verified_at: string;
  fixed?: string[];
  still_present?: string[];
  evidence?: string;
}

// ActionsView — the action list + a fix-verification roll-up ("we confirm fixes, not just propose them").
export interface ActionsView {
  actions: Action[];
  applied: number;
  verified: number;
  confirmed_fix: number;
  still_present: number;
  /**
   * Fixes the re-scan found gone but which are NOT counted as confirmed, because a clean re-scan for
   * that class has been contradicted by a live exploit before (ADR 0025 F1). A third state — neither
   * a confirmed fix nor a failed one — so it must never be folded into either.
   */
  awaiting_proof: number;
  /** Approved actions whose apply attempt failed — they are stuck, not pending. */
  failed_delivery: number;
  /** Rule classes whose clean re-scans this tenant's own history shows have been contradicted. */
  distrusted_classes?: DistrustedClass[];
  /**
   * (finding class, remediation type) pairings that most often FAILED to close, worst first — the
   * runbooks to rewrite. Distinct from distrusted_classes, which is about our RE-SCAN being wrong;
   * this is about the FIX being wrong.
   */
  weakest_remediations?: WeakRemediation[];
}

// DistrustedClass — where our own absence-evidence has measurably failed.
export interface DistrustedClass {
  class: string;
  contributors: number;
  clean_rescans: number;
  contradicted: number;
}

// AssetCoverage — the per-asset "what was actually tested" statement (visibility most teams lack).
export interface AssetCoverage {
  asset_id: string;
  target: string;
  type: string;
  scanned: boolean;
  last_scanned_at?: string;
  runs_tools: string[]; // the tools every scan of this type runs
  tools_with_findings: string[]; // which surfaced a finding
  // Whether per-tool execution was VERIFIED for this asset. False means runs_tools is the
  // DECLARED toolset and nothing may be concluded about whether each tool actually ran — so the
  // heading must not say "tools run on every scan". Its Go doc says this field exists "so the UI
  // states what is known rather than the reassuring version"; it was ignored here until #1285.
  execution_confirmed?: boolean;
  // Tools this scan dispatched that produced NO RESULT — a per-tool timeout, a crash, or a
  // binary missing from the sandbox image. Critically NOT the same as "ran and found nothing":
  // a tool that never ran has no opinion about the target, and rendering it as clean is the
  // one thing this page exists to prevent.
  tools_failed?: { tool: string; reason?: string }[];
  findings_count: number;
  // Classes this asset's scan cannot reach without an operator-declared config that is absent.
  // Present so "no findings" is never read as "nothing to find" — BOLA/BFLA need two identities.
  untested_classes?: ConfigGatedClass[];
  // What THIS scan, against THIS target, hit and could not test. Distinct from
  // untested_classes: that is a standing limitation of the asset TYPE, knowable before any
  // scan; a declared gap is a fact about a specific run. Rendered separately so a standing
  // caveat cannot absorb a live one.
  declared_gaps?: DeclaredGap[];
  // Whether ANY finding could be tied to this asset's target. Attribution matches the target
  // inside the endpoint, which cannot work for a repository — its findings are file-relative.
  attributed: boolean;
  // Findings from tools this asset type runs that tied to no asset at all. Evidence that a
  // zero finding count is an attribution failure rather than a clean scan.
  unattributable_from_our_tools?: number;
}
// DeclaredGap carries its detail VERBATIM. The wording is where the "this is a coverage
// gap, not a vulnerability" caveat lives, and summarising it is exactly where that would
// be lost — so the UI prints it rather than paraphrasing.
export interface DeclaredGap {
  title: string;
  detail?: string;
  endpoint?: string;
  rule?: string;
}
export interface ConfigGatedClass {
  class: string;
  reference?: string;
  needs_config: string;
  configure_at?: string;
}
export interface CoverageSummary {
  assets: AssetCoverage[];
  total_assets: number;
  scanned_assets: number;
}

// Risk register — the vCISO judgment artifact. The engine proposes candidates (Proposed); a named
// human decides treatment (accept/mitigate/transfer/avoid), recorded with owner + rationale + ledger.
export interface Risk {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  category?: string;
  likelihood: number; // 1-5
  impact: number; // 1-5
  treatment?: string; // accept | mitigate | transfer | avoid
  status: string; // open | accepted | treating | closed
  owner?: string;
  rationale?: string;
  finding_ids?: string[];
  proposed?: boolean; // agent-seeded candidate, awaiting human triage
  created_at: string;
  decided_at?: string;
  decided_by?: string;
  ledger_ref?: string;
  capacity?: string; // who the deciding human works for: internal | msp | managed
  firm?: string;
}

export interface RiskSummary {
  total: number;
  open: number;
  accepted: number;
  treating: number;
  closed: number;
  proposed: number;
  by_level: Record<string, number>;
  top_risk_id?: string;
}

export interface RisksResponse {
  risks: Risk[];
  summary: RiskSummary;
}

// Audit engagement — the SOC2/ISO audit run WITH an external auditor. The product seeds the controls
// to attest from posture; a named independent auditor renders each verdict (the legal layer).
export interface ControlAttestation {
  framework: string;
  control_id: string;
  verdict: string; // pending | passed | exception
  note?: string;
  attested_by?: string;
  attested_at?: string;
  capacity?: string; // who the attester works for: internal | msp | managed
  firm?: string;
}

export interface AuditSummary {
  total: number;
  attested: number;
  passed: number;
  exceptions: number;
  pending: number;
  percent: number;
  ready: boolean;
}

export interface AuditEngagement {
  id: string;
  tenant_id: string;
  framework: string;
  audit_type: string; // type_i | type_ii
  auditor_name?: string;
  auditor_firm?: string;
  auditor_email?: string;
  status: string; // planning | fieldwork | issued
  attestations?: ControlAttestation[];
  created_at: string;
  issued_at?: string;
  ledger_ref?: string;
  summary: AuditSummary; // the API embeds the per-engagement summary
}

export interface AuditsResponse {
  audits: AuditEngagement[];
}

// Security program (vCISO) — the policy register + acknowledgments. The engine seeds the standard set;
// a named owner publishes (HITL), and each member acknowledges.
export interface PolicyAck {
  user: string;
  acked_at: string;
}

export interface Policy {
  id: string;
  tenant_id: string;
  name: string;
  category?: string;
  summary?: string;
  status: string; // draft | published
  owner?: string;
  capacity?: string; // who the publishing owner works for: internal | msp | managed
  firm?: string;
  version: number;
  acks?: PolicyAck[];
  created_at: string;
  published_at?: string;
  ledger_ref?: string;
}

export interface ProgramSummary {
  total: number;
  published: number;
  draft: number;
  team_size: number;
  fully_acked: number;
  ack_coverage_pct: number;
}

export interface ProgramResponse {
  policies: Policy[];
  summary: ProgramSummary;
}

// Practitioner — the named human who provides the human-in-the-loop for a tenant. Capacity (who
// employs them) is the only thing that differs between the MSP-channel and managed-service models.
export interface Practitioner {
  id: string;
  name: string;
  firm?: string;
  credential?: string;
  capacity: string; // internal | msp | managed
  email?: string;
  scope?: string[];
}

export interface PractitionersResponse {
  service_model: string; // self_serve | msp | managed
  practitioners: Practitioner[];
}

// The CERT-In six-hour reporting position for an incident (India). Present only when the
// incident's opening finding is a CERT-In Annexure I reportable category — absent means no
// reporting duty, never a false "you are late to a regulator" state.
export interface CERTInStatus {
  due_at: string;
  reported: boolean;
  reported_at?: string;
  breached: boolean;
  minutes_left: number; // negative once the six-hour window has closed
  categories: string[];
}

export interface Incident {
  id: string;
  key: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string; // open | resolved
  finding_id: string;
  verification?: string; // FP-control: verified | corroborated | pattern_match (carried from the finding)
  confidence?: number; // 0..1 quality scalar — so an unconfirmed alert never looks like a confirmed one
  // blast_radius: read-time impact sizing — does this incident chain to a crown jewel, and how far away?
  blast_radius?: { reaches_crown_jewel: boolean; crown_jewel_type?: string; hops?: number };
  attacked?: boolean; // escalated because the issue is under attack in production
  // Consecutive authoritative scans in which this incident's issue did not appear, reset the moment
  // it reappears. Non-zero on an OPEN incident means the fix is being confirmed, not that nothing
  // has happened — and without it the queue renders "still firing" and "gone from the last scan,
  // holding until the absence repeats" identically. That matters most to the person who just
  // deployed a fix and is looking for whether it worked: seeing the alert unchanged reads as the
  // fix having failed. The hysteresis exists because one quiet scan is not proof (measured on
  // WAVSEP: dalfox found 7 cases in one run and 9 in the next on an unchanged target, succeeding
  // both times, so no failure signal fired).
  absent_passes?: number;
  // WHEN the state behind this incident changed, read from the estate timeline at request time and
  // never persisted (the timeline grows after an incident opens, so a frozen onset would go stale).
  //
  // It is the difference between two alerts that otherwise render identically: "this bucket is
  // public" is a fact that gets triaged next week, "this bucket became public forty minutes ago" is
  // something someone deals with now. `at` is when we FIRST OBSERVED the change — state is compared
  // between captures, so it happened somewhere in the interval before that, and `note` says so.
  // Absent when the timeline has nothing grounded to say (a near-miss is left unannotated rather
  // than attached to the wrong resource).
  onset?: { at: string; what: string; resource_id: string; note?: string };
  // Ransomware use is a STRICTLY STRONGER claim than KEV listing — exploited in the wild versus
  // exploited by crews who encrypt the estate — which is why the corpus keeps them separate and only
  // CISA's literal "Known" counts. A queue that shows neither makes the responder rank by severity
  // alone, which is the number that knows least about who is using this.
  // The base exploitation signal. kev_due_at and ransomware were added while THIS was still
  // undeclared, so the queue could show a CISA deadline without being able to say the CVE is
  // known-exploited — the fact the deadline follows from.
  kev?: boolean;
  ransomware?: boolean;
  // CISA's OWN published BOD 22-01 due date, carried verbatim as an ABSOLUTE deadline rather than a
  // window from when we opened the incident. That distinction is the point: a KEV CVE catalogued six
  // months ago is already past its deadline, and a fresh window would tell a customer they have a
  // fortnight when the government's answer is that they are months late. Showing nothing tells them
  // less than either.
  kev_due_at?: string;
  // Detection Skill triage (ADR 0017): the detection engineer's reasoning carried onto the alert, so
  // whoever is on shift inherits it instead of rediscovering it. triage_skill is "name@digest" —
  // provenance, so you can see exactly which skill version said this.
  // ANNOTATION ONLY: a verdict never opened or closed this incident, it only explains it.
  triage_verdict?: string; // malicious | suspicious | inconclusive | benign
  triage_rationale?: string;
  triage_skill?: string;
  opened_at: string;
  resolved_at?: string;
  acknowledged_at?: string; // a human took ownership → stops timed auto-escalation
  acknowledged_by?: string;
  sla_breach?: SLABreach; // read-time SLA state vs the tenant's policy (absent = not tracked)
  certin?: CERTInStatus; // read-time CERT-In six-hour reporting position (India); absent = not a reportable category
}

export interface SLATarget {
  severity: string; // critical | high | medium | low
  ack_hours: number;
  resolve_hours: number;
}
export interface SLAPolicy {
  enabled: boolean;
  targets: SLATarget[];
}
export interface SLABreach {
  severity: string;
  ack_due_at?: string;
  resolve_due_at?: string;
  ack_breached: boolean;
  resolve_breached: boolean;
  // WHY the clock is short. All three exist for this consumer — their Go docs say so in as many
  // words ("so the UI can say WHY the clock is short instead of showing an unexplained deadline";
  // "rather than leaving a reader to assume we are being dramatic") — and none of them were declared
  // here, so the badge said "SLA resolve breached" and nothing else. An unexplained deadline is the
  // thing they were added to prevent.
  kev_accelerated?: boolean; // deadline came from CISA BOD 22-01, not the severity target
  ransomware_accelerated?: boolean; // deadline came from the ransomware clock (stricter still)
  cisa_deadline?: boolean; // an absolute date CISA published, not a window we derived
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  starts_at: string;
  ends_at: string;
  reason?: string;
  created_by?: string;
}

// On-call escalation roster entry (GET /v1/contacts) — who the escalation matrix names.
export interface Contact {
  id: string;
  name: string;
  role?: string;
  email?: string;
  phone?: string;
  order: number;
}

// SOC-performance scorecard (GET /v1/soc-metrics) — grounded in incident timestamps.
export interface SOCMetrics {
  generated_at: string;
  open_incidents: number;
  resolved_incidents: number;
  acknowledged: number;
  unacknowledged: number;
  sla_tracked: number;
  sla_compliant: number;
  sla_breached: number;
  sla_compliance_pct: number;
  mtta_hours: number;
  mttr_hours: number;
  aging_under_1d: number;
  aging_1_7d: number;
  aging_over_7d: number;
}

export interface Connection {
  id: string;
  kind: string;
  status: string;
  account?: string;
  config?: Record<string, string>;
  created_at?: string;
}

export interface EscalationTier {
  min_severity: string; // critical | high | medium | low
  channels: string[]; // slack | pagerduty | teams | discord | webhook
}
export interface EscalationPolicy {
  enabled: boolean;
  ack_window_mins: number;
  tiers: EscalationTier[];
}

export interface PlanLimits {
  plan: string;
  label: string;
  max_assets: number; // -1 = unlimited
  ai_enabled: boolean;
  autonomous_pentest: boolean;
  all_frameworks: boolean;
  continuous_monitoring: boolean; // the unattended re-scan heartbeat (on-demand scanning is separate)
  human_in_loop_apply: boolean;
}

export interface Tenant {
  id: string;
  name: string;
  plan?: string;
  created_at?: string;
  agents_halted?: boolean; // global kill-switch: when true, no autonomous agent action runs
  // The resolved entitlements, so a surface never has to infer them from the plan string — which is
  // exactly how the pricing page and the backend drifted apart.
  limits?: PlanLimits;
}

// AI-BOM (agent capability manifest, WRD-1): what the autonomous agent can touch.
export interface AIBomConnection {
  id: string;
  kind: string;
  account?: string;
  status: string; // "active" | "quarantined" | "degraded" | "revoked"
  scopes?: string[];
  write_scopes?: string[];
  capability: "read-only" | "read-write";
}
export interface AIBom {
  governance: { kill_switch_engaged: boolean; gate_tier: number };
  connections: AIBomConnection[] | null; // Go nil slice → null
  summary: { connections: number; write_capable: number; read_only: number };
}

// A user account within a tenant (password hash never sent by the API).
export interface User {
  id: string;
  tenant_id: string;
  email: string;
  name?: string;
  role: string; // "owner" | "member"
  created_at: string;
  must_change_password?: boolean; // invited member with a temp password; app is gated until they rotate it
}

// Public Trust Center aggregate (safe projection — coverage only, never findings).
export interface TrustView {
  org: string;
  monitored: boolean;
  signed: boolean;
  // coverage = ASSESSMENT coverage (assessed/assessable %), not a met/total "score" — keeps the public page
  // honest (never a green "100% compliant" to the tenant's customers).
  frameworks: { framework: string; coverage: number; assessed: number; assessable: number; gaps: number }[] | null; // Go nil slice → null
  generated_at: string;
}

export interface TrustLink {
  tenant: string;
  token: string;
  path: string;
}

export interface Engagement {
  id: string;
  asset_id: string;
  trigger: string;
  scan_id?: string;
  started_at: string;
  completed_at?: string;
}

// Human-expert review request (platform.ReviewRequest — snake_case json tags).
export interface ReviewRequest {
  id: string;
  subject: string; // "finding" | "action"
  subject_id: string;
  note: string;
  requester?: string;
  status: string; // open | resolved
  resolution?: string;
  reviewer?: string;
  created_at: string;
  resolved_at?: string;
}

// Security questionnaire (grc.Questionnaire — snake_case json tags).
export interface QAnswer {
  id: string;
  domain: string;
  text: string;
  controls?: Record<string, string[]>;
  answer: string; // "Yes" | "In Progress"
  gap_controls?: string[];
  evidence_ids?: string[];
  missing_sources?: string[]; // what to connect to make an unanswered question answerable
}
export interface Questionnaire {
  tenant_id: string;
  generated_at: string;
  answers: QAnswer[] | null; // Go nil slice → null
  yes: number;
  in_progress: number;
  not_assessed: number; // questions with no connected evidence source — refused, not assumed compliant
}

export interface Asset {
  id: string;
  connection_id: string;
  type: string; // repository | cloud_account | web_application | api | container_image | ip_address | domain | mobile_application | workspace
  target: string;
  meta?: Record<string, string>;
  discovered_at?: string;
  data_tier?: number; // 1 = customer data, 2 = standard, 3 = low sensitivity
  data_tier_label?: string;
}

export interface ControlState {
  framework: string;
  control_id: string;
  state: string; // met | gap | exception
  evidence_refs?: string[];
}

// One framework's compliance summary (met/gap/total). Returned in a batch by GET /v1/posture so
// the dashboard/compliance/reports pages fetch all frameworks in one call instead of 14.
export interface FrameworkPosture {
  framework: string;
  total: number; // assessed controls (met+gap)
  met: number;
  gap: number;
  // Coverage honesty — so the UI shows "X of Y assessed" and never reads a clean posture as "compliant".
  assessable: number; // controls our tooling CAN assess for this framework
  not_assessed: number;
  coverage_pct: number; // assessed / assessable, 0..100
  certifiable: boolean; // ALWAYS false — automated scanning is not a certification
  readiness: string; // honest status line, never "Compliant"
}
export interface PostureSummary {
  frameworks: FrameworkPosture[];
}

// Bring-your-own-framework — tenant-defined frameworks whose posture is derived from live findings.
export interface CustomControl {
  id: string;
  name?: string;
  maps_to?: string[]; // "cwe:CWE-89" | "rule:secrets" | "soc2:CC6.1"
}
export interface CustomFramework {
  id: string;
  name: string;
  description?: string;
  controls: CustomControl[];
}
// Compliance scope (before-analysis) — what the customer is pursuing + their applicability profile.
export interface ComplianceProfile {
  handles_phi: boolean;
  processes_cards: boolean;
  sells_to_gov: boolean;
  eu_data_subjects: boolean;
  india_data_subject: boolean;
  public_company: boolean;
}
export interface ComplianceScope {
  target_frameworks: string[];
  compliance_profile: ComplianceProfile;
  suggested: string[];
}

export interface CustomFrameworkPosture {
  framework: CustomFramework;
  controls: ControlState[];
  coverage: { assessable_controls: number; assessed_controls: number; not_assessed: number; gaps: number; coverage_pct: number; certifiable: boolean; readiness: string };
  note: string;
}

// Compliance scoping — the connect-this-first readiness checklist (GET /v1/compliance/readiness).
export interface IntegrationNeed {
  category: string;
  label: string;
  connectors: string;
  unlocks: string;
  connected: boolean;
}
export interface ComplianceReadiness {
  target_frameworks: string[];
  integrations: IntegrationNeed[];
  manual_areas: IntegrationNeed[]; // important asset/control areas tsengine doesn't automate (attestation)
  connected: number;
  recommended: number;
  note: string;
}

// Per-asset compliance signal ("is this asset compliant?") — grc.AssetPosture. Grounded: an asset is only
// attributed when a finding's endpoint contains its target; status NEVER says bare "compliant".
export interface AssetPosture {
  asset_id: string;
  target: string;
  type: string;
  attributed: boolean;
  finding_count: number;
  gap_controls: number;
  frameworks: string[];
  worst_severity: string;
  status: string;
}
export interface ComplianceByAsset {
  assets: AssetPosture[];
  total: number;
  attributed: number;
}

// Per-asset SECURITY posture ("is this asset secure?") — crossdetect.AssetSecurity. FP-aware
// (confirmed vs unconfirmed) + coverage (scanned) + impact; verdict NEVER a bare "secure".
export interface AssetSecurity {
  asset_id: string;
  target: string;
  type: string;
  scanned: boolean;
  attributed: boolean;
  findings: number;
  confirmed: number; // verified or corroborated — act on these
  unconfirmed: number; // single-tool pattern_match — confirm first
  critical: number;
  high: number;
  worst_severity: string;
  verdict: string;
}
export interface SecurityByAsset {
  assets: AssetSecurity[];
  total: number;
  at_risk: number;
}

// grc.Report JSON (no json tags on the Go struct → PascalCase keys).
export interface ReportEvidence { FindingID: string; Title: string; Severity: string }
export interface ReportRow { ControlID: string; State: string; Gap: boolean; Evidence?: ReportEvidence[] }
export interface ComplianceReport {
  TenantName: string;
  Title: string;
  Framework: string;
  GeneratedAt: string;
  Rows: ReportRow[] | null; // Go marshals an empty slice as null — callers must guard
  MetCount: number;
  GapCount: number;
  // Coverage is the honesty layer (Go field has no json tag → PascalCase key; inner fields are snake_case).
  Coverage?: {
    assessable_controls: number;
    assessed_controls: number;
    not_assessed: number;
    gaps: number;
    automated_coverage_pct: number;
    certifiable: boolean;
    readiness: string;
  };
  Signer?: string;
  SHA256?: string;
}

// ComplianceSnapshot — one point on a framework's continuous-evidence timeline (mirrors
// platform.ComplianceSnapshot). Append-only: an auditor reads these as continuity proof.
export interface ComplianceSnapshot {
  id: string;
  tenant_id: string;
  framework: string;
  captured_at: string;
  total_controls: number;
  met_controls: number;
  gap_controls: number;
  state_hash: string;
  fully_met: boolean;
}

// EvidenceTimeline — the continuous-evidence view for a framework (mirrors grc.EvidenceTimeline):
// the ordered snapshots + a continuity summary (fully-met ratio, the captured window).
export interface EvidenceTimeline {
  framework: string;
  snapshots: ComplianceSnapshot[] | null; // Go marshals an empty slice as null — guard it
  count: number;
  first_captured_at?: string;
  last_captured_at?: string;
  fully_met_ratio: number;
  continuous: boolean;
}

export interface SaaSApp {
  name: string;
  count: number;
  scopes: string[];
  admin_consent: boolean;
  verified: boolean;
  sensitive: boolean;
  shadow_it: boolean;
}

// TrainingSettings is the workspace's standing decision on whether its agent runs may be
// used to improve the product (ADR 0018 §4). `statement` is what was actually agreed to,
// stored verbatim; `current_statement` is what a yes would agree to today, so the UI shows
// the customer the real words rather than a label we maintain separately and can drift from.
export interface TrainingSettings {
  consented: boolean;
  by?: string;
  at?: string;
  statement?: string;
  current_statement: string;
  note: string;
}

// EpisodeStats rolls up the scored-agent-run corpus (GET /v1/episodes). `scored` is
// deliberately reported next to `episodes`: the gap is the share of runs whose effect could
// not be measured, and every number derived from the rest has to be read against it.
export interface EpisodeStats {
  episodes: number;
  scored: number;
  trainable: number;
  cost_usd: number;
  verified: number;
  cost_per_verified?: number;
  has_cost_per_verified: boolean;
  opened: number;
  closed: number;
}

// PRBotSettings is the repository PR-review-bot policy. block_severity is the merge-gating floor
// ("off" = comment-only); github_connected reports whether the live post is wired to a GitHub App.
export interface PRBotSettings {
  enabled: boolean;
  block_severity: string;
  github_connected: boolean;
}

// Non-human / AI-agent identity posture (GET /v1/identities) — the ACSP agentic identity lens.
export interface NonHumanIdentity {
  name: string;
  class: string; // ai_agent | automation | integration
  privilege: string; // admin | write | read
  scopes: string[];
  users: number;
  verified: boolean;
  risk: string; // high | medium | low
  risk_reason?: string;
}
export interface IdentitiesResponse {
  identities: NonHumanIdentity[];
  summary: { total: number; ai_agents: number; automations: number; write_or_admin: number; risky: number };
}

export interface SaaSAppsResponse {
  apps: SaaSApp[];
  summary: {
    total_apps: number;
    sensitive_apps: number;
    unverified_apps: number;
    shadow_it_apps: number;
    multi_user_apps: number;
  };
}

// ProofRequest — one finding the AI Security Engineer routed to the AI Pentester to settle.
// Mirrors internal/pentest.ProofRequest (snake_case on the wire).
export type ProofRequest = {
  finding_id: string;
  target: string;
  class: string;
  severity: string;
  why: string;
};


// AIChoice is one selectable AI mode, with what it does and what it costs. Unavailable choices carry
// a `why` rather than just greying out — a control that refuses without explaining sends the customer
// looking in the wrong place.
export interface AIChoice {
  mode: string;
  label: string;
  detail: string;
  cost: string;
  available: boolean;
  why?: string;
}

// AIModeResponse is the AI-engine control surface: what is running, why, the options, and the money.
export interface AIModeResponse {
  mode: string;
  engineer: boolean;
  pentester: boolean;
  // Did the customer PICK this mode, or is it just what they were left with? A Free workspace with no
  // key resolves to "deterministic" having chosen nothing, and looks identical to someone who chose it
  // deliberately — so mode alone cannot tell you whether nudging them toward AI is helpful or rude.
  chosen: boolean;
  reason: string;
  choices: AIChoice[];
  spend_usd: number;
  runs: number;
  using_own_key: boolean;
  budget_usd: number;
  remaining_usd: number;
}

// DatabaseScanResult — a one-shot Postgres inventory scan (Supabase / Neon / RDS / self-hosted).
//
// credential_retained is part of the contract, not decoration: someone pasting a production
// connection string is owed a plain statement of what happened to it.
export interface DatabaseScanResult {
  tables: number;
  grants: number;
  issues_detected: number;
  schemas_scanned?: string[];
  findings: Finding[];
  note?: string;
  credential_retained: boolean;
  credential_note?: string;
  // What the classifier PROVED about the data, per object — not a checkbox someone ticked.
  //
  // Declared as string[] while the server sends objects, which nothing caught because nothing read
  // it. Anyone wiring it up would have got [object Object] in the UI.
  //
  // evidence names the column and the signal and never echoes a raw value, so this is auditable
  // without leaking the data it is about.
  discovered_sensitive?: { object: string; classes: string[]; evidence: string[] }[];
  deeper_scan_available?: string;
}

/** A background job (a scan run). Surfaced so a scan that FAILED is visible — a failed scan that
 *  shows nothing reads as "no vulnerabilities found", which is the worst possible misreading. */
export interface Job {
  id: string;
  tenant_id: string;
  kind: string;
  status: string; // queued | running | done | failed
  error?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
}

/** One reason the current view may be incomplete or the product is not acting.
 *
 *  Computed server-side so a new reason is visible by default. The three defects this replaces were
 *  each a signal the backend held and no page rendered; keeping the list on the server means a page
 *  cannot forget to fetch one. */
export interface Degradation {
  kind: string;
  severity: "critical" | "warning" | "info";
  title: string;
  detail: string;
  action_label?: string;
  action_href?: string;
  /** who can act on this: "both" | "tenant" | "operator". The API already filters to the
   *  caller's audience (ADR 0022 §2) — this is here so a client can style by it, never to hide. */
  audience?: string;
}

export interface SystemState {
  degradations: Degradation[];
}

/** One security practice a company at a given funding stage is expected to have.
 *
 *  `evidence` is the load-bearing field: only an `observed` row may read pass/fail, because only
 *  those are answered by a scanner. `attested` needs a person, `capability` needs switching on, and
 *  `unbuilt` is one we do not cover — rendering all four the same colour would be a lie. */
export interface ReadinessItem {
  id: string;
  category: string;
  tier: "seed" | "series_a" | "series_b" | "series_c";
  text: string;
  evidence: "observed" | "capability" | "attested" | "unbuilt";
  status: "pass" | "gap" | "not_checked" | "needs_you" | "not_covered";
  detail: string;
  needs?: string[];
  tools?: string[];
  instead?: string;
  why?: string;
  agent?: "engineer" | "pentester";
  gap_count?: number;
  attested_by?: string;
  attested_at?: string;
}

export interface ReadinessSummary {
  stage: string;
  total: number;
  pass: number;
  gap: number;
  not_checked: number;
  needs_you: number;
  not_covered: number;
}

export interface ReadinessChecklist {
  stage: string;
  stage_set: boolean;
  summary: ReadinessSummary;
  items: ReadinessItem[];
  stages: { value: string; label: string; detail: string }[];
}

/** Severity counts only. The shell renders a risk badge from this instead of pulling every finding —
 *  measured at 27MB per page load for a workspace that imported a 50,000-finding backlog. */
export interface FindingsSummary {
  total: number;
  severity: Record<string, number>;
  truncated: boolean;
}

// The L1.5 audit surface — what the AI suppressed or changed, and the evidence to judge it by.
export interface L15AuditRule {
  rule: string;
  action: string;
  count: number;
}
export interface L15Audit {
  entries: {
    finding_id: string;
    action: string;
    from_severity?: string;
    to_severity?: string;
    rule: string;
    reason?: string;
  }[];
  // The dropped findings themselves — the only ones with no row anywhere else in the product.
  suppressed: Finding[];
  total: number;
  dropped: number;
  demoted: number;
  by_rule: L15AuditRule[];
  scans_with_audit: number;
  scans_total: number;
  // Present when nothing was recorded — an empty trail is not evidence nothing was suppressed.
  note?: string;
}

// The tenant's OWN eval suite — graded from decisions they already made, not a vendor benchmark.
export interface TenantEvalCase {
  finding_id: string;
  rule_id: string;
  source: "reinstated" | "ignored" | "confirmed_fix";
  expect: "keep" | "suppress";
  by?: string;
  reason?: string;
}
export interface TenantEvalFailure extends TenantEvalCase {
  got: "keep" | "suppress";
}
export interface TenantEvalTrend {
  // False whenever a comparison would mislead — one sample, or a graded set that changed between
  // runs. Show `note` instead of a delta.
  comparable: boolean;
  delta_points?: number;
  direction?: "improved" | "regressed" | "unchanged";
  note: string;
  runs: number;
}

export interface TenantEval {
  cases: number;
  suite_hash?: string;
  trend?: TenantEvalTrend;
  passed: number;
  failures: TenantEvalFailure[];
  by_source: Partial<Record<"reinstated" | "ignored" | "confirmed_fix", number>>;
  // Absent when there are no cases — an empty suite has NO score, because a vacuous 100% would
  // rise as a customer does less.
  agreement?: number;
  note?: string;
}

// FixEfficacy — the measured track record of one kind of remediation against one kind of finding.
export interface FixEfficacy {
  closed: number;
  not_closed: number;
  /** Applications whose re-scan said gone but was not accepted as confirmation (F1). Not a success
   *  and not a failure — excluded from the rate, reported so the sample size is honest. */
  unproven?: number;
  /** A track record EXISTS but cannot be scored — too few applications were ever confirmed either
   *  way. Distinct from absence, and must not be rendered as it. */
  muted?: boolean;
}

// WeakRemediation — a fix that keeps not closing the thing it claimed to close.
export interface WeakRemediation {
  class: string;
  remediation_type: string;
  closed: number;
  not_closed: number;
  unproven?: number;
}

// AttackTechnique / AttackCoverage — which ATT&CK techniques were exercised against this estate.
// "not_exercised" is NOT clean: nobody checked. Counts only, never a percentage — the denominator is
// tsengine's own tool set, so a percentage would measure us against ourselves.
export interface AttackTechnique {
  id: string;
  name?: string;
  tools: string[];
  status: "observed" | "exercised_clean" | "not_exercised";
  findings?: number;
  why?: string;
}
export interface AttackCoverage {
  techniques: AttackTechnique[];
  observed: number;
  exercised_clean: number;
  not_exercised: number;
  denominator: string;
}

// ExposureTrend — is exposure going down? "closed" counts issues that STOPPED APPEARING, which a
// descoped asset and a degraded scan also produce; only confirmed_fixed rests on a re-test.
export interface ExposurePoint {
  day: string;
  opened: number;
  closed: number;
  persisted: number;
  episodes: number;
  unscored: number;
}
export interface ExposureTrend {
  points: ExposurePoint[];
  confirmed_fixed: number;
  unscored: number;
  scopes_included?: string[];
  mixed?: boolean;
  caveat: string;
}

// DetectionValidation — when we proved an attack works, did the customer's own defences notice?
//
// "undetermined" is NOT a miss and must never render as one: an undeployed sensor, late telemetry and
// a genuine miss are indistinguishable, so only `not_detected` accuses a control.
export interface DetectionResult {
  canary: string;
  target: string;
  verdict: "detected" | "not_detected" | "undetermined";
  /** "marker" = the sensor reported OUR token (exact). "correlated" = endpoint+class+timing (an inference). */
  strength?: "marker" | "correlated";
  /** The control INTERVENED rather than merely observing. Monitor-only is a different answer. */
  blocked?: boolean;
  why?: string;
  event_id?: string;
}
export interface DetectionValidation {
  results: DetectionResult[];
  detected: number;
  not_detected: number;
  undetermined: number;
  blocked: number;
  caveat: string;
}
