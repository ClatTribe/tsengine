// Package platform holds the multi-tenant domain model for the autonomous security
// team product (docs/autonomous-team.md). These types wrap — never replace — the
// engine's scan/finding contract (pkg/types): the engine finds & proves issues; the
// platform layer owns tenancy, the connected systems it watches, the continuous
// engagements it runs, the remediations it proposes, the human approvals it gates,
// and the GRC control state it maintains.
//
// The package is deliberately dependency-light (stdlib + pkg/types + pkg/ledger — both
// of which are themselves leaves) so the store, connector, scheduler, hitl, remediate,
// and grc packages can all share it without a cycle. pkg/ledger is here for the episode
// record's delta and cost blocks: re-declaring those shapes locally would give the
// system two definitions of the same thing, and they would drift.
package platform

import (
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Tenant is one customer organization. Every other entity is scoped to a TenantID;
// the store enforces isolation on that key.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// AgentsHalted is the global kill-switch (agentic-SMB spec OM-3 / TS-5): when true,
	// the platform performs NO autonomous agent action for this tenant — no new scans and
	// no remediation writes (auto-applied or human-approved alike). It fails closed: a
	// halted tenant's actions queue instead of executing until a human disengages it. The
	// one human "on the loop" can freeze the whole roster instantly.
	AgentsHalted bool `json:"agents_halted,omitempty"`
	// MonthlyAIBudgetUSD is a hard ceiling on what the AI agents may cost this calendar month, in USD.
	// 0 means no ceiling.
	//
	// l2.Budget already bounds a single RUN; this bounds the month, which is the number a founder
	// actually needs to predict. Unpredictable spend is a real reason people decline to switch AI on at
	// all, so the ability to say "never more than fifty dollars" is what makes saying yes safe.
	//
	// When it is reached the agents STOP and the product SAYS SO — it never silently returns thinner
	// results, because a customer who cannot tell "the budget ran out" from "the agent found nothing"
	// has been told their estate is clean when it was not examined.
	MonthlyAIBudgetUSD float64 `json:"monthly_ai_budget_usd,omitempty"`
	// AIMode is the customer's own choice of how much AI to run. See AIMode.
	//
	// Distinct from the PLAN (what they are entitled to) and from AgentsHalted (an emergency
	// freeze). This is a standing preference: a tenant entitled to both agents may deliberately
	// run deterministic-only — for cost, for a trust ramp, or because they are not ready to send
	// their code to a model. The zero value means "not chosen", which resolves to whatever the
	// plan allows, so every existing tenant is unaffected.
	AIMode AIMode `json:"ai_mode,omitempty"`
	// LLM is the tenant's bring-your-own-LLM config for the agent / autonomous pentest. The
	// API key is sealed (LLMConfig.KeyRef holds only the sealed ref); it is NEVER returned to
	// the client — Redacted() strips it, and every tenant response uses that.
	LLM *LLMConfig `json:"llm,omitempty"`
	// LLMRoles are OPTIONAL per-role model overrides (see AgentRole). A role absent here falls back to
	// LLM above, so this is purely additive — an existing tenant is unaffected. Each entry's key is
	// sealed exactly like LLM's, and Redacted() drops the whole map for the same reason.
	LLMRoles map[AgentRole]*LLMConfig `json:"llm_roles,omitempty"`
	// PRBot is the per-tenant policy for the repository PR-review bot (ADR 0010). nil = the
	// default (disabled). The live GitHub post is separately gated on the GitHub App PR scope.
	PRBot *PRBotPolicy `json:"pr_bot,omitempty"`
	// Training is the customer's standing decision about whether their agent runs may be
	// used to improve the system (ADR 0018 §4). nil = NOT consented, which is the correct
	// default and the only safe one: silence is not agreement, and a corpus that treats it
	// as agreement is one nobody can defend afterwards.
	//
	// The decision is read when an episode STARTS and stamped onto it there. That is why
	// it lives on the Tenant rather than being asked per run: consent has to be in hand
	// before the data exists, and ledger.GrantConsent refuses once an episode has closed
	// precisely so it cannot be back-filled.
	Training *TrainingConsent `json:"training,omitempty"`
	// PostureAssessed records when each snapshot-driven posture source (tprm, deviceposture,
	// clouddrift) last ran, keyed by its tool tag. It exists because those assessors are grounded —
	// a well-managed estate yields ZERO findings — which makes "assessed and clean" and "never
	// ingested" byte-identical in the findings store. Without this stamp the UI cannot tell them
	// apart, and it showed the reassuring reading ("this posture source is clean") for both. An
	// entry appears only after a real ingest, so ABSENCE means not-assessed, never clean (§10).
	//
	// sspm (SaaS posture) and osint (external exposure) were missing from BOTH halves — not listed
	// as posture sources and not stamped by any door — while their findings flowed into issues
	// normally. Both are grounded the same way, so a customer whose GitHub org was properly
	// configured saw the same empty posture as one who had never connected. Every listed source now
	// has a stamping door, asserted by a test, because a source shown with nothing stamping it can
	// only ever read "not tested" — including for the customer who ran it.
	PostureAssessed map[string]time.Time `json:"posture_assessed,omitempty"`
	// SlackWebhookRef is the secret.Vault-sealed ref for this tenant's OWN Slack Incoming Webhook —
	// where THIS tenant's new-incident heads-ups go (per-tenant routing; the operator-env webhook is
	// the fallback). A webhook URL is a bearer capability, so it is sealed, never plaintext at rest,
	// and never returned to the client — Redacted() strips it; HasSlackWebhook() reports presence.
	SlackWebhookRef string `json:"slack_webhook_ref,omitempty"`
	// Jira is the tenant's OWN Jira instance where file_ticket remediations land (per-tenant; the
	// operator-env Jira is the fallback). BaseURL/Email/Project are plain identifiers; the API token
	// is sealed (TokenRef). Redacted() drops the whole block.
	Jira *JiraConfig `json:"jira,omitempty"`
	// Escalation is the per-tenant incident escalation matrix (the MDR/SOC "who is alerted, how
	// urgently" for a new incident). nil/disabled = today's behaviour (alert every configured
	// channel). No secret material — channel names only.
	Escalation *EscalationPolicy `json:"escalation,omitempty"`
	// ExposureObjective is the programme's stated target for the exposure trend — CTEM's scoping
	// question ("how is success measured?"), which the product could show a series for and not answer.
	//
	// nil means no objective, and that is reported as itself rather than defaulted: a target nobody
	// chose is not a statement of intent, and "we cannot say whether this is good" is the honest
	// reading of a chart with no target. No secret material.
	ExposureObjective *ExposureObjective `json:"exposure_objective,omitempty"`
	// SLA is the per-tenant remediation SLA policy (per-severity time-to-acknowledge +
	// time-to-resolve targets). nil/disabled = no SLA tracking. No secret material.
	SLA *SLAPolicy `json:"sla,omitempty"`
	// MaintenanceWindows are planned change-freeze periods. While one is active, the detector
	// opens no new incidents and the escalation matrix pages no one (so a planned deploy doesn't
	// trip the SOC). Resolves still flow. Empty = always-on monitoring.
	MaintenanceWindows []MaintenanceWindow `json:"maintenance_windows,omitempty"`
	// Contacts is the on-call roster — the people the escalation matrix names (the contractual
	// "escalation matrix with contact number"). Ordered by escalation precedence. Contact PII
	// (email/phone), not a bearer secret, so stored plain like team-member emails.
	Contacts []Contact `json:"contacts,omitempty"`
	// BusinessServices map critical business services to the assets that carry them — CTEM's scoping
	// phase (ADR 0028 G2). DataTier says an asset is tier 1; only this says CHECKOUT depends on it,
	// and it is the service that has an owner and someone who gets paged. No secret → stored plain,
	// like Contacts and Practitioners.
	BusinessServices []BusinessService `json:"business_services,omitempty"`
	// ServiceModel records WHO provides the human-in-the-loop expertise for this tenant — the only
	// difference between the two product GTM models. self_serve = the tenant's own team; msp = a
	// partner firm's expert (the MSP runs the product, their expert does HITL); managed = our hired
	// expert acting on the tenant's behalf. Empty = self_serve.
	ServiceModel string `json:"service_model,omitempty"`
	// Practitioners are the named experts of record who provide the HITL acts (risk decisions,
	// attestations, sign-offs, policy publishing) for this tenant. Each carries a Capacity matching
	// the service model. No bearer secret → stored plain (like Contacts).
	Practitioners []Practitioner `json:"practitioners,omitempty"`
	// TargetFrameworks is the compliance scope the customer is actually pursuing (e.g. ["soc2","hipaa"]).
	// Captured BEFORE analysis so the posture, coverage, and "what to connect" readiness focus on what
	// the customer needs — not all 14. Empty = no declared scope (the UI shows the full catalog). Keys
	// match grc.Frameworks. No secret → stored plain.
	TargetFrameworks []string `json:"target_frameworks,omitempty"`
	// Stage is the customer's declared funding stage (seed | series_a | series_b | series_c), which
	// decides WHICH security practices they are measured against. Deliberately separate from Plan:
	// Plan is what they pay us, Stage is what their company needs, and conflating the two would
	// measure a well-funded seed team against an enterprise bar because they bought the big tier.
	Stage string `json:"stage,omitempty"`
	// ReadinessAttestations answer the practices no scan can observe — whether production access is
	// gated behind just-in-time elevation, whether every change is reviewed. A named human answers;
	// it is never inferred from findings. Keyed by practice id.
	ReadinessAttestations map[string]ReadinessAttestation `json:"readiness_attestations,omitempty"`
	// QuestionnaireAttestations answer the security-questionnaire questions no scan can reach —
	// background checks, physical security, whether the recovery plan was actually tested. A
	// named human answers and the rendered document says so, because an assertion and an
	// observation must never look alike to a buyer.
	//
	// A SEPARATE map from ReadinessAttestations rather than a shared one: the two have distinct
	// id namespaces (a readiness practice and a questionnaire question can both be "BC-1"), and
	// merging them would let an answer given for one purpose silently answer the other.
	QuestionnaireAttestations map[string]QuestionnaireAttestation `json:"questionnaire_attestations,omitempty"`
	// ComplianceProfile holds the applicability facts that determine which frameworks/controls are in
	// scope — handles PHI (HIPAA), processes card data (PCI), sells to government (FedRAMP/800-171),
	// EU/India data subjects (GDPR/DPDP). Drives framework suggestions + scoping. No secret → plain.
	ComplianceProfile *ComplianceProfile `json:"compliance_profile,omitempty"`
	// CustomFrameworks are tenant-defined frameworks ("bring your own framework" — Vanta/Sprinto parity
	// for the long regional/sector tail). Each control maps to our existing findings (by built-in
	// framework:control, CWE, or rule id), so a custom framework's posture is DERIVED from live findings
	// — never asserted. No secret → stored plain on the Tenant (like Contacts/Practitioners).
	CustomFrameworks []CustomFramework `json:"custom_frameworks,omitempty"`
	// TrustCenter is the buyer-facing share page's configuration — which documents are offered,
	// at which gate, under which NDA. nil = the page serves only the aggregate posture it always
	// has, so an existing tenant is unaffected. No secret material (the buyer access tokens live
	// hashed on TrustAccessRequest, never here) → stored plain, like Contacts and SLA.
	TrustCenter *TrustCenterConfig `json:"trust_center,omitempty"`
}

// CustomFramework is a tenant-defined compliance framework. Its controls map to signals tsengine already
// produces, so it flows through the same grounded posture/coverage machinery as the built-in 22.
type CustomFramework struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Controls    []CustomControl `json:"controls"`
}

// CustomControl is one control of a custom framework. MapsTo lists the signals that, if any appears in the
// tenant's findings, make this control a GAP — each entry is "fw:control" (a built-in framework control,
// e.g. "soc2:CC6.1"), "cwe:CWE-89", or "rule:<rule-id-substring>". Empty MapsTo → the control can only be
// satisfied by manual attestation (never auto-met, never auto-gap — honest, no false-compliant).
type CustomControl struct {
	ID     string   `json:"id"`
	Name   string   `json:"name,omitempty"`
	MapsTo []string `json:"maps_to,omitempty"`
}

// ComplianceProfile is the set of applicability facts a customer answers ONCE, up front — the scoping
// questions a consultant asks before any analysis. Each maps to which frameworks actually apply.
type ComplianceProfile struct {
	HandlesPHI       bool `json:"handles_phi"`        // → HIPAA in scope
	ProcessesCards   bool `json:"processes_cards"`    // → PCI-DSS in scope
	SellsToGov       bool `json:"sells_to_gov"`       // → FedRAMP / NIST 800-171 in scope
	EUDataSubjects   bool `json:"eu_data_subjects"`   // → GDPR in scope
	IndiaDataSubject bool `json:"india_data_subject"` // → India DPDP in scope
	PublicCompany    bool `json:"public_company"`     // → SOX ITGC in scope
}

// Service models — who employs the human-in-the-loop.
const (
	ServiceSelfServe = "self_serve" // the tenant's own team runs the HITL (default)
	ServiceMSP       = "msp"        // a partner firm's expert runs the HITL (the MSP uses our product)
	ServiceManaged   = "managed"    // our hired expert runs the HITL on the tenant's behalf
)

// Practitioner capacities (who the named expert works for).
const (
	CapacityInternal = "internal" // the tenant's own person
	CapacityMSP      = "msp"      // a partner firm's expert
	CapacityManaged  = "managed"  // our delivery expert, acting for the tenant
)

// Practitioner is a named human who provides the human-in-the-loop expertise for a tenant. The
// Capacity (who employs them) is the load-bearing field: it's the only thing that differs between the
// "MSP runs our product" model and the "we provide the expert" model. Recording the practitioner of
// record makes the HITL artifacts honest about who acted and in what capacity (independence for
// audits, accountability for pentests).
type Practitioner struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Firm       string   `json:"firm,omitempty"`       // the practitioner's firm (the MSP, our delivery org, or the tenant)
	Credential string   `json:"credential,omitempty"` // e.g. "CPA", "OSCP", "CISSP", "vCISO"
	Capacity   string   `json:"capacity"`             // internal | msp | managed
	Email      string   `json:"email,omitempty"`
	Scope      []string `json:"scope,omitempty"` // deliverables they cover: vciso|audit|pentest|risk (empty = all)
}

// Contact is one entry in the on-call escalation roster — who to reach, in what order. Phone is the
// PO's literal "contact number"; live SMS/voice paging is gated (Bucket C), but the roster + numbers
// are first-class so the escalation matrix names real people.
type Contact struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Role  string `json:"role,omitempty"` // e.g. "Security Lead", "On-call engineer"
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"` // contact number (SMS/voice delivery is Bucket-C)
	Order int    `json:"order"`           // escalation precedence (lower = contacted first)
}

// MaintenanceWindow is a planned period during which alerting is suppressed (a change-freeze /
// deploy window — standard MDR/SOC operations). No secret material.
type MaintenanceWindow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	Reason    string    `json:"reason,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Active reports whether now falls within the window ([StartsAt, EndsAt)).
func (w MaintenanceWindow) Active(now time.Time) bool {
	return !now.Before(w.StartsAt) && now.Before(w.EndsAt)
}

// InMaintenance reports whether the tenant has any maintenance window active at now (so alerting
// should be suppressed). Returns the first active window for context.
func (t Tenant) InMaintenance(now time.Time) (MaintenanceWindow, bool) {
	for _, w := range t.MaintenanceWindows {
		if w.Active(now) {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// HasSlackWebhook reports whether the tenant has configured its own Slack incident webhook.
func (t Tenant) HasSlackWebhook() bool { return t.SlackWebhookRef != "" }

// EscalationPolicy is the per-tenant incident escalation matrix — the MDR/SOC "who is alerted, and
// how urgently" for a newly-opened incident (PagerDuty/Opsgenie parity + the contractual
// "escalation matrix with contact number"). When Enabled, the incident alerter routes a new
// incident to the channels of the FIRST tier whose MinSeverity the incident meets; if it is not
// acknowledged within AckWindowMins, it escalates to the next tier (timed auto-escalation —
// Phase 2). Disabled/nil = today's behaviour (alert every configured channel on every incident).
type EscalationPolicy struct {
	Enabled       bool             `json:"enabled"`
	AckWindowMins int              `json:"ack_window_mins,omitempty"` // 0 = no timed auto-escalation
	Tiers         []EscalationTier `json:"tiers"`
}

// EscalationTier routes incidents at/above MinSeverity to Channels. Tiers are ordered: tier 0 is
// the first responder; later tiers are escalation targets.
type EscalationTier struct {
	MinSeverity string   `json:"min_severity"` // critical | high | medium | low
	Channels    []string `json:"channels"`     // slack | pagerduty | teams | email | webhook
}

// SLAPolicy is the per-tenant remediation SLA — the time-to-acknowledge + time-to-resolve targets
// a managed-security buyer expects (and the AAI-PO "24x7 SOC" implies: a serious issue must be
// owned and fixed inside a contracted window). Every MDR / vuln-mgmt competitor ships per-severity
// SLAs; this is that, grounded on the incident timestamps (OpenedAt / AcknowledgedAt / ResolvedAt).
type SLAPolicy struct {
	Enabled bool        `json:"enabled"`
	Targets []SLATarget `json:"targets"`
	// KEVResolveHours is the CISA BOD 22-01 style override: a vulnerability the
	// KEV catalog lists as EXPLOITED IN THE WILD gets a hard remediation deadline
	// regardless of its CVSS severity tier (being exploited in the wild is itself
	// the deadline). It applies only to an incident really flagged KEV by the
	// pinned corpus (§10), can only TIGHTEN (the stricter of severity-target vs
	// KEV window wins), and applies even when the severity has no target at all.
	// 0 disables it.
	KEVResolveHours int `json:"kev_resolve_hours,omitempty"`
	// RansomwareResolveHours is the tighter clock for a CVE CISA marks as used in
	// RANSOMWARE campaigns. It is a strictly stronger fact than KEV listing —
	// "exploited in the wild" versus "exploited by crews who encrypt you by
	// Monday" — and most of the KEV catalog is the former only, so giving the two
	// one clock would either understate the urgent few or panic the rest. 0
	// disables it and the KEV clock applies as before.
	RansomwareResolveHours int `json:"ransomware_resolve_hours,omitempty"`
}

// SLATarget is the per-severity window. Hours (not minutes) — SLAs are coarse. 0 = no target for
// that clock (e.g. AckHours 0 → acknowledgement is not SLA-tracked for this severity).
type SLATarget struct {
	Severity     string `json:"severity"`      // critical | high | medium | low
	AckHours     int    `json:"ack_hours"`     // hours from open to acknowledge
	ResolveHours int    `json:"resolve_hours"` // hours from open to resolve
}

// SLABreach is the evaluated SLA state of one incident against the policy.
type SLABreach struct {
	Severity        string    `json:"severity"`
	AckDueAt        time.Time `json:"ack_due_at,omitzero"`
	ResolveDueAt    time.Time `json:"resolve_due_at,omitzero"`
	AckBreached     bool      `json:"ack_breached"`     // not acknowledged in time
	ResolveBreached bool      `json:"resolve_breached"` // not resolved in time
	// KEVAccelerated records that the resolve deadline came from the KEV override
	// (BOD 22-01) rather than the severity target, so the UI can say WHY the clock
	// is short ("exploited in the wild") instead of showing an unexplained deadline.
	KEVAccelerated bool `json:"kev_accelerated,omitempty"`
	// RansomwareAccelerated records that the deadline came from the ransomware
	// clock, so the UI can say WHY it is this short rather than leaving a reader to
	// assume we are being dramatic.
	RansomwareAccelerated bool `json:"ransomware_accelerated,omitempty"`
	// CISADeadline records that the deadline is CISA's OWN published due date for
	// this CVE, used verbatim rather than computed. Distinct from the others
	// because it is an absolute date set by an authority, not a window we derived.
	CISADeadline bool `json:"cisa_deadline,omitempty"`
}

// BlastRadius is the impact-sizing signal for a finding/incident — does it sit on a cross-surface attack
// chain that reaches a crown jewel (e.g. cloud root), and how many hops away. Derived from the same
// correlate chains as /attack-paths (grounded — no new detection); absent when the finding is on no
// crown-jewel chain (its impact is just its own severity). Defined here so it can ride as a transient
// read-time annotation on Incident, like SLABreach.
type BlastRadius struct {
	ReachesCrownJewel bool   `json:"reaches_crown_jewel"`
	CrownJewelType    string `json:"crown_jewel_type,omitempty"` // e.g. cloud_account
	Hops              int    `json:"hops,omitempty"`             // steps from this finding to the crown jewel
}

// Breached reports whether either clock is breached.
func (b SLABreach) Breached() bool { return b.AckBreached || b.ResolveBreached }

// TargetFor returns the SLA target for a severity (exact match). ok=false when there is no target.
func (p *SLAPolicy) TargetFor(severity string) (SLATarget, bool) {
	if p == nil || !p.Enabled {
		return SLATarget{}, false
	}
	for _, t := range p.Targets {
		if t.Severity == severity {
			return t, true
		}
	}
	return SLATarget{}, false
}

// Evaluate computes the SLA state of an incident against the policy. ok=false when SLA tracking does
// not apply (no policy / disabled / no target for the severity). Grounded on the incident clocks:
//   - ack breach: the incident is not yet acknowledged AND now is past OpenedAt+AckHours;
//   - resolve breach: the incident is not resolved AND now is past OpenedAt+ResolveHours.
//
// A met clock never breaches (an acknowledged incident has no ack breach; a resolved one has no
// resolve breach). A 0-hour target disables that clock. now is injected so it is testable.
func (p *SLAPolicy) Evaluate(inc Incident, now time.Time) (SLABreach, bool) {
	tgt, ok := p.TargetFor(inc.Severity)
	// Exploitation overrides (BOD 22-01 and its ransomware tier): an incident flagged
	// KEV gets a hard resolve deadline even when its severity has no target at all.
	kevHours, ransomHours := 0, 0
	if p != nil && p.Enabled && inc.KEV {
		kevHours = p.KEVResolveHours
		if inc.Ransomware {
			ransomHours = p.RansomwareResolveHours
		}
	}
	hasCISADue := p != nil && p.Enabled && inc.KEV && !inc.KEVDueAt.IsZero()
	if !ok && kevHours <= 0 && ransomHours <= 0 && !hasCISADue {
		return SLABreach{}, false
	}
	b := SLABreach{Severity: inc.Severity}
	if ok && tgt.AckHours > 0 {
		b.AckDueAt = inc.OpenedAt.Add(time.Duration(tgt.AckHours) * time.Hour)
		b.AckBreached = !inc.Acknowledged() && now.After(b.AckDueAt)
	}
	resolveHours := 0
	if ok {
		resolveHours = tgt.ResolveHours
	}
	// The exploitation clocks can only TIGHTEN, strongest signal last: KEV listing,
	// then ransomware use, which is the stricter claim.
	if kevHours > 0 && (resolveHours <= 0 || kevHours < resolveHours) {
		resolveHours, b.KEVAccelerated = kevHours, true
	}
	if ransomHours > 0 && (resolveHours <= 0 || ransomHours < resolveHours) {
		resolveHours = ransomHours
		b.KEVAccelerated, b.RansomwareAccelerated = false, true
	}
	if resolveHours > 0 {
		b.ResolveDueAt = inc.OpenedAt.Add(time.Duration(resolveHours) * time.Hour)
	}
	// CISA's OWN due date is ABSOLUTE, not a window from when we happened to notice.
	// This matters: a KEV CVE catalogued six months ago is already past its deadline,
	// and computing a fresh window from OpenedAt would silently restart a clock the
	// authority already ran out — telling a customer they have two weeks when the
	// government's answer is that they are months late.
	if hasCISADue && (b.ResolveDueAt.IsZero() || inc.KEVDueAt.Before(b.ResolveDueAt)) {
		b.ResolveDueAt = inc.KEVDueAt
		b.CISADeadline = true
		b.KEVAccelerated, b.RansomwareAccelerated = false, false
	}
	if !b.ResolveDueAt.IsZero() {
		b.ResolveBreached = inc.Status != IncidentResolved && now.After(b.ResolveDueAt)
	}
	return b, true
}

// severityRank orders severities so a tier's MinSeverity floor can be compared. Higher = worse.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ChannelsFor returns the channels the FIRST matching tier routes a new incident of the given
// severity to (tiers evaluated in order; a tier matches when the incident severity ≥ its
// MinSeverity). Returns (nil, false) when the policy is nil/disabled/empty or nothing matches —
// the caller then falls back to its default alerting. Pure, so it's unit-tested directly.
func (p *EscalationPolicy) ChannelsFor(severity string) (channels []string, matched bool) {
	if p == nil || !p.Enabled || len(p.Tiers) == 0 {
		return nil, false
	}
	sev := severityRank(severity)
	for _, t := range p.Tiers {
		if sev >= severityRank(t.MinSeverity) && len(t.Channels) > 0 {
			return t.Channels, true
		}
	}
	return nil, false
}

// JiraConfig is a tenant's own Jira ticketing destination. BaseURL/Email/Project are plain;
// TokenRef is the secret.Vault-sealed ref for the API token (never plaintext, never returned).
type JiraConfig struct {
	BaseURL  string `json:"base_url"`
	Email    string `json:"email"`
	Project  string `json:"project"`
	TokenRef string `json:"token_ref,omitempty"`
}

// HasToken reports whether a usable Jira destination is configured (without exposing the token).
func (j *JiraConfig) HasToken() bool {
	return j != nil && j.BaseURL != "" && j.Email != "" && j.Project != "" && j.TokenRef != ""
}

// PRBotPolicy is the per-tenant repository PR-review-bot policy: whether to post inline review
// comments + a merge-gating check-run on a pull request, and the severity at/above which the
// check-run FAILS (blocks merge). No secret material — safe to return to the client.
type PRBotPolicy struct {
	Enabled bool `json:"enabled"`
	// BlockSeverity is the merge-gating floor: a finding at/above it fails the check-run.
	// "" or "off" = comment-only (advisory, never blocks). Else: critical|high|medium|low.
	BlockSeverity string `json:"block_severity"`
}

// LLMConfig is a tenant's configured LLM for engine agent work (the L2 agent, ModeDeep
// pentest, the live bench). Provider/Model are plain; KeyRef is the secret.Vault-sealed ref
// for the API key (never plaintext at rest, never returned to the client — §18.2 inv. 6).
type LLMConfig struct {
	Provider string `json:"provider"` // anthropic | openai | gemini | ollama | openai-compat
	Model    string `json:"model"`    // e.g. claude-opus-4-8, gpt-4o, gemini-2.0-flash, llama3.1
	// BaseURL is the endpoint for a SELF-HOSTED OpenAI-compatible model (Ollama / vLLM / LM Studio),
	// e.g. http://localhost:11434/v1. Not a secret (an endpoint, like Jira.BaseURL) → stored plain.
	// Empty for cloud providers (they use their vendor default).
	BaseURL string `json:"base_url,omitempty"`
	KeyRef  string `json:"key_ref,omitempty"`
}

// AgentRole names the KIND of reasoning an L2 agent does, so a tenant can point different agents at
// different models. The split is not cosmetic — the two lanes reward genuinely different training:
//
//   - RoleCode is code and exploitation reasoning (patch generation, the XBOW-style pursuit, spec
//     synthesis). General frontier models are strongest here, and it is exactly the work the
//     defensive-security model vendors say their models are NOT for.
//   - RoleAnalysis is reasoning OVER security data that tools already produced — triage, correlation,
//     attack-path narration, control mapping. This is the lane a security-specialized model targets:
//     large volumes of findings/logs/graph, weak signals, consistency across many decisions.
//
// A deployment can therefore run a small self-hosted security model for analysis (cheap, private,
// sovereign) while keeping a frontier model for code — instead of paying frontier prices for triage or
// accepting an 8B model's patch quality. Unset roles fall back to the tenant's single LLM config, so
// this is additive: an existing tenant behaves exactly as before.
type AgentRole string

const (
	// RoleAnalysis — triage, correlation, compliance mapping, attack-path reasoning.
	RoleAnalysis AgentRole = "analysis"
	// RoleCode — patch generation, exploitation, code and spec reasoning.
	RoleCode AgentRole = "code"
)

// AgentRoles is the closed set, for validation and for the settings UI.
func AgentRoles() []AgentRole { return []AgentRole{RoleAnalysis, RoleCode} }

// ValidAgentRole reports whether s names a known role.
func ValidAgentRole(s string) bool {
	for _, r := range AgentRoles() {
		if string(r) == s {
			return true
		}
	}
	return false
}

// SelfHosted reports whether this config points at a self-hosted OpenAI-compatible endpoint (which
// may legitimately have NO API key — Ollama doesn't require one).
func (c *LLMConfig) SelfHosted() bool { return c != nil && strings.TrimSpace(c.BaseURL) != "" }

// Usable reports whether this config can actually drive an agent: it needs either an API key (cloud)
// or a self-hosted endpoint (Ollama et al. legitimately have no key). A config with neither is inert,
// and callers must fall back rather than build a client that cannot reach anything.
func (c *LLMConfig) Usable() bool { return c != nil && (c.HasKey() || c.SelfHosted()) }

// LLMForRole returns the config that should drive the given role: the tenant's per-role override when
// one is set AND usable, else the tenant's single default. Returns nil when neither exists, so the
// caller falls back to the operator-global model.
//
// Grounded fallback (§10 in spirit): a role override that carries neither a key nor an endpoint is
// treated as ABSENT rather than honoured, so a half-filled override can never silently disable an
// agent that the tenant's default config could have driven.
func (t Tenant) LLMForRole(role AgentRole) *LLMConfig {
	if c, ok := t.LLMRoles[role]; ok && c.Usable() {
		return c
	}
	if t.LLM.Usable() {
		return t.LLM
	}
	return nil
}

// HasKey reports whether an API key is configured (without exposing it).
func (c *LLMConfig) HasKey() bool { return c != nil && c.KeyRef != "" }

// Redacted returns a copy of the tenant safe to return to a client: the LLM block (which
// carries the sealed key ref) is dropped. LLM provider/model are served only by the dedicated
// GET /v1/settings/llm endpoint.
func (t Tenant) Redacted() Tenant {
	t.LLM = nil
	t.LLMRoles = nil // per-role overrides carry sealed key refs too — same reason as LLM
	t.SlackWebhookRef = ""
	t.Jira = nil
	return t
}

// Connection kinds — the external systems the platform can link via OAuth.
const (
	ConnGitHub      = "github"
	ConnGitLab      = "gitlab"
	ConnBitbucket   = "bitbucket"
	ConnAzureDevOps = "azuredevops"
	ConnAWS         = "aws"
	ConnGCP         = "gcp"
	ConnAzure       = "azure"
	ConnGWorkspace  = "gworkspace"
	ConnM365        = "m365"
	ConnOkta        = "okta"
	ConnSlack       = "slack"
)

// Connection statuses.
const (
	ConnActive   = "active"
	ConnDegraded = "degraded"
	ConnRevoked  = "revoked"
	// ConnQuarantined is a human-set, per-connection kill-switch (agentic-SMB spec WRD-4):
	// the agent takes NO action through this one connection (no scans, no writes) while the
	// rest of the roster keeps running. Like every non-active status it fails the connection
	// closed in the runner + deliverer.
	ConnQuarantined = "quarantined"
)

// Connection is an OAuth-linked external system the agent watches and (for gated
// write actions) acts on. The OAuth token itself is NEVER stored inline — SecretRef
// points at the secret store (KMS-envelope for the MVP).
type Connection struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	Kind      string   `json:"kind"`   // ConnGitHub | ConnAWS | ...
	Status    string   `json:"status"` // ConnActive | ConnDegraded | ConnRevoked
	Scopes    []string `json:"scopes,omitempty"`
	SecretRef string   `json:"secret_ref"` // → secret store, opaque to the platform
	Account   string   `json:"account,omitempty"`
	// Config holds per-connection, NON-secret configuration the customer sets via UX — today the
	// cloud-remediation knobs (remediation_enabled + the customer's own cross-account write role:
	// remediation_role_arn/region for AWS, remediation_impersonate_sa for GCP). These are
	// identifiers, not credentials (like Account), so they live here in the clear; anything
	// actually secret goes through SecretRef/the Vault. Nil for connections that need none.
	Config    map[string]string `json:"config,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// CloudRemediationConfig keys (Connection.Config) — the per-tenant, customer-set cloud write role.
const (
	CfgRemediationEnabled = "remediation_enabled"        // "true" → use the per-tenant write path
	CfgRemediationRole    = "remediation_role_arn"       // AWS: the customer's cross-account write role
	CfgRemediationRegion  = "remediation_region"         // AWS: region for the write call (optional)
	CfgRemediationSA      = "remediation_impersonate_sa" // GCP: the write SA to impersonate
)

// Asset is something discovered under a Connection — a repo, a cloud account, a
// domain. Type uses the engine's asset-type vocabulary (pkg/types.AssetType) so the
// orchestrator can scan it directly.
type Asset struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	ConnectionID string            `json:"connection_id"`
	Type         string            `json:"type"` // repository | cloud_account | web_application | ...
	Target       string            `json:"target"`
	Meta         map[string]string `json:"meta,omitempty"`
	// Owner and Team are who to route a finding on this asset to (ADR 0028 G1). Owner exists on Risk
	// and Policy — the vCISO artifacts — so the product could say who ACCEPTED a risk and not who
	// should fix the finding underneath it.
	//
	// Empty means UNOWNED, and that is a real answer rather than a missing one. Falling back to the
	// tenant owner so every ticket has an assignee manufactures accountability: it names someone who
	// never agreed to it, and it hides the fact a scoping exercise most needs to surface. Contact
	// metadata like Contact, not a credential — stored plain, and never an authorization input, or an
	// unowned asset becomes an unprotectable one.
	Owner        string    `json:"owner,omitempty"`
	Team         string    `json:"team,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Engagement trigger kinds.
const (
	TriggerSchedule = "schedule"
	TriggerPush     = "push"
	TriggerDeploy   = "deploy"
	TriggerManual   = "manual"
)

// Engagement is one continuous-monitoring run over an Asset. It wraps an engine scan
// (ScanID → pkg/types.Scan) and points at the signed decision ledger for the run.
type Engagement struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AssetID     string    `json:"asset_id"`
	Trigger     string    `json:"trigger"`
	ScanID      string    `json:"scan_id,omitempty"`
	LedgerRef   string    `json:"ledger_ref,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitzero"`

	// L15Audit is every change the L1.5 chain made to this scan's findings — each demotion,
	// dismissal and merge with the rule that caused it and why (§2.5: those decisions must be
	// "logged + recoverable" so the security engineer can audit and override them).
	//
	// It is the one part of the scan that cannot be reconstructed afterwards. A stored finding
	// still carries its own RawOutput and ToolArgs, so what a tool said about a SURVIVING finding
	// is recoverable — but a finding the FP filter dropped leaves no trace at all, and a demoted
	// one shows only its new severity. Recording the trail is what lets a security engineer see
	// what the AI decided not to show them, and disagree with it.
	L15Audit []types.AuditEntry `json:"l15_audit,omitempty"`
	// L15Dismissed are the findings the chain DROPPED on this scan, kept so a security engineer can
	// review the AI's judgement and REINSTATE one it got wrong (§2.5: the audit log exists "for
	// override"). Without the finding itself, the trail can only say what was suppressed, never put
	// it back — half an affordance.
	L15Dismissed []types.Finding `json:"l15_dismissed,omitempty"`

	// ToolsRan and ToolsFailed record what the scan ACTUALLY dispatched, as opposed to what the
	// asset type is configured to run.
	//
	// Without them the platform could not distinguish a tool that ran and found nothing from one
	// that timed out or was absent from the image — so /coverage told the customer "All tools ran
	// and found nothing" on scans where tools had silently been dropped. Measured: four identical
	// api scans returned 1, 1, 11 and 11 findings with three different toolsets.
	//
	// Empty ToolsRan means the runner did not report execution (e.g. the operate path, which uses no
	// sandbox tools), NOT that nothing ran — absence of data is not evidence of absence (§10).
	ToolsRan    []string            `json:"tools_ran,omitempty"`
	ToolsFailed []types.ToolFailure `json:"tools_failed,omitempty"`
}

// Action kinds — how a remediation is delivered.
const (
	ActOpenPR      = "open_pr"
	ActApplyConfig = "apply_config"
	ActRevokeToken = "revoke_token"
	ActFileTicket  = "file_ticket"
	// ActDraftNotification is the A-RSP incident-response artifact: a DRAFT breach /
	// disclosure communication the agent prepares for a confirmed critical incident. It is
	// always tier-3 (irreversible/legal) — a named human edits and signs it before it is
	// filed or sent; the agent never sends regulatory/customer comms on its own.
	ActDraftNotification = "draft_notification"
)

// Action statuses.
const (
	ActProposed        = "proposed"
	ActPendingApproval = "pending_approval"
	ActApproved        = "approved"
	ActApplied         = "applied"
	ActRejected        = "rejected"
	// ActChangesRequested is the reviewer's THIRD verdict, and the one a senior engineer actually
	// reaches for most often: "almost — change this."
	//
	// With only approve/reject, a reviewer who spots one wrong line has to destroy the whole proposal
	// to say so. That trains two bad habits: rubber-stamping (rejecting throws away work that was 90%
	// right) and disengagement (the desk stops being worth reading). Both turn human-in-the-loop into
	// theatre, which is the opposite of the §18.2 inv. 3 intent.
	//
	// A changes-requested action is NOT applied and NOT closed: it stays actionable, carries the
	// reviewer's Feedback, and can be re-proposed. The gate is unchanged — this verdict can only ever
	// withhold an apply, never cause one.
	ActChangesRequested = "changes_requested"
)

// Action is a remediation the agent proposes. Tier is the autonomy tier (§3 of the
// agentic-SMB spec): 0=observe, 1=reversible/low, 2=consequential, 3=irreversible/
// legal. Tier ≥ 2 must be human-gated before it is applied.
type Action struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"` // the representative finding (always set — grounding)
	// FindingIDs is the full set a *bulk* action resolves (≥2). Empty for a single-
	// finding action; when set, FindingID is the first/representative of this set. A
	// bulk fix (one PR addressing many related alerts) carries every finding it fixes.
	FindingIDs   []string       `json:"finding_ids,omitempty"`
	ConnectionID string         `json:"connection_id,omitempty"` // the connection that delivers this action
	Kind         string         `json:"kind"`                    // ActOpenPR | ActApplyConfig | ...
	Tier         int            `json:"tier"`                    // 0..3
	Status       string         `json:"status"`                  // ActProposed | ActPendingApproval | ...
	Title        string         `json:"title,omitempty"`
	Payload      map[string]any `json:"payload,omitempty"`
	Approver     string         `json:"approver,omitempty"`
	LedgerRef    string         `json:"ledger_ref,omitempty"`
	// Diff is the unified diff this action would apply, rendered for a human to READ before
	// approving. It exists because the payload is an untyped map: a reviewer approving an ActOpenPR
	// was approving a code change they could not see, which is not a review — it is a signature.
	//
	// Empty for actions that change no code (a ticket, a notification draft). Never a substitute for
	// the payload: the payload is what gets applied, Diff is the human-readable rendering of it, so a
	// mismatch is a rendering bug and can never alter what is executed.
	Diff string `json:"diff,omitempty"`
	// Feedback is the reviewer's note when they request changes — the "change this one thing" that
	// approve/reject cannot express. Carried back so the next proposal can act on it.
	Feedback string `json:"feedback,omitempty"`
	// ReviewedBy / ReviewedAt record who asked for changes and when. Distinct from Approver/DecidedAt,
	// which mean the action was finally decided; a changes-requested action is still open.
	ReviewedBy string    `json:"reviewed_by,omitempty"`
	ReviewedAt time.Time `json:"reviewed_at,omitzero"`
	// Supersedes is the id of the action this one re-proposes after changes were requested, so the
	// desk shows a review THREAD rather than two unrelated rows.
	Supersedes string `json:"supersedes,omitempty"`
	// FindingKeys are the STABLE identities (rule_id|endpoint) of the findings this action
	// resolves — captured at propose time so the fix can be re-tested after it's applied. Stable
	// across scans (finding IDs are regenerated per scan; keys are not). Drives FixVerification.
	FindingKeys  []string         `json:"finding_keys,omitempty"`
	Verification *FixVerification `json:"verification,omitempty"` // set once the applied fix is re-tested
	// VerificationHistory is the APPEND-ONLY record of every materially different verdict this action
	// has received. Verification above is the current one; this is what actually happened.
	//
	// It exists because deriving evidence from current state silently FORGETS. ApplyReattack replaces
	// Verification wholesale, so an action contradicted in one pass and re-verified clean in a later
	// one lost the contradiction entirely — and a contradiction is precisely the fact
	// internal/fieldevidence exists to remember. Worse, the erasure biased toward TRUST and grew
	// stronger the more diligently a customer fixed things.
	VerificationHistory []FixVerification `json:"verification_history,omitempty"`
	// DeliveryError is why the last apply attempt failed, redacted and bounded.
	//
	// Without it a delivery failure was INVISIBLE: hitl.Desk deliberately leaves a failed action at
	// ActApproved ("approved but not applied"), which from the actions list is indistinguishable from
	// one merely waiting to be applied. So a customer configured Jira, a ticket was filed, it never
	// arrived, and nothing said why — they would look in Jira, see nothing, and have no way to learn
	// the delivery failed. The ledger recorded apply_failed, so it was auditable; it just was not
	// surfaced anywhere the customer looks.
	//
	// Cleared on a successful apply, so a retry that works leaves no stale explanation behind.
	DeliveryError string    `json:"delivery_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	DecidedAt     time.Time `json:"decided_at,omitzero"`
	// ApplyBlocked is a KNOWN reason this action could not be applied if approved right now —
	// computed at READ time from the connector's Preflight (never persisted, like Incident's
	// SLABreach). It exists so the console can warn the human BEFORE they approve, rather than
	// letting them approve a remediation that is structurally incapable of running and only
	// learning after the click.
	//
	// Empty means "no known blocker", NOT "guaranteed to work": a connector may not implement
	// Preflight at all, and the provider can still deny the call (§10).
	ApplyBlocked string `json:"apply_blocked,omitempty"`
	// FixEfficacy is a READ-TIME annotation (never persisted, like ApplyBlocked): what this tenant's
	// own history says about whether THIS kind of fix has actually closed THIS kind of finding
	// before (ADR 0025 F2). Nil when there is not enough history to say — rendering "0 of 0" beside
	// a proposed fix would read as a fix that never works, which is the opposite of what an absence
	// of data means.
	FixEfficacy *FixEfficacy `json:"fix_efficacy,omitempty"`
}

// FixVerification records whether an APPLIED remediation actually closed the findings it claimed
// to fix — the answer to KF#4 ("60% don't retest after fixes; a fix that isn't verified is a fix
// taken on trust"). It is produced by re-testing the action's finding keys against a fresh,
// authoritative scan. Grounded (§10): a fix is "fixed" ONLY when every key it claimed to resolve
// is provably absent from the current scan; "still_present" when any remain (the fix didn't work
// — reopen). Never assumed — an action with no finding keys is simply left un-verified.
// Fix-verification statuses, and the discovery method a human reinstatement stamps. These are
// CONSTANTS because they are read in one package and written in another, and a bare literal on each
// side drifts silently the moment either changes. That is not hypothetical here: the eval suite's
// suppression source matched nothing for every tenant because it rebuilt an issue key by hand
// instead of calling the function that assigns it, and its test passed because the fixture encoded
// the same mistake. Same coupling, same failure mode — so it gets a name.
const (
	FixStatusFixed        = "fixed"
	FixStatusStillPresent = "still_present"
	// FixStatusRescanUnconfirmed: every finding was GONE from the re-scan, but for this rule class a
	// clean re-scan has measurably been contradicted by a live exploit before (ADR 0025 F1), so the
	// re-scan alone is not accepted as the terminal "fixed" claim. Deliberately NOT terminal — a
	// re-attack can still settle it either way. It says "gone, on evidence we know has failed for
	// this class", which is a different statement from both "fixed" and "still present" and must not
	// be rendered as either.
	FixStatusRescanUnconfirmed = "rescan_unconfirmed"
	// DiscoveryHumanReinstated marks a finding a person put back after the filter dropped it — the
	// strongest correction signal the product records.
	DiscoveryHumanReinstated = "human_reinstated"
)

type FixVerification struct {
	Status       string    `json:"status"` // FixStatusFixed | FixStatusStillPresent | FixStatusRescanUnconfirmed
	Method       string    `json:"method"` // "rescan" — re-ran detection and compared keys
	VerifiedAt   time.Time `json:"verified_at"`
	Fixed        []string  `json:"fixed,omitempty"`         // finding keys confirmed gone from the fresh scan
	StillPresent []string  `json:"still_present,omitempty"` // finding keys STILL found (the fix did not close them)
	Evidence     string    `json:"evidence,omitempty"`      // human-readable, e.g. "3 of 3 confirmed fixed in re-scan"
	// RescanSaidFixed records what the ABSENCE check concluded, independently of what the
	// re-attack then proved. Kept because the two disagreeing is the single most valuable
	// thing this system can learn: it is a labelled example that absence-evidence was not
	// enough, and it is the only way to answer "what evidence is sufficient" from real data
	// rather than from opinion.
	RescanSaidFixed bool `json:"rescan_said_fixed,omitempty"`
	// Disagreement names HOW the two kinds of evidence conflicted, machine-readably. The
	// prose in Evidence already explained it to a human; this exists so the conflict can be
	// counted and learned from without regexing English.
	Disagreement string `json:"disagreement,omitempty"`
}

// Evidence-conflict kinds. Both mean a verification method was insufficient, and they are
// separate because they indict DIFFERENT methods and have different fixes.
const (
	// DisagreeRescanMissedLiveExploit: the re-scan reported the finding gone and the exploit
	// still works. The dangerous direction — a customer was one step from being told they
	// were safe. Indicts absence-as-evidence.
	DisagreeRescanMissedLiveExploit = "rescan_missed_live_exploit"
	// DisagreeScannerSeesVariant: the exploit no longer works but the scanner still reports
	// the finding. Indicts the re-test playbook, which may not cover the variant the scanner
	// sees. Not dangerous, but not closure either.
	DisagreeScannerSeesVariant = "scanner_sees_variant"
)

// GateTier is the autonomy tier at/above which an Action must be human-approved
// before it is applied. Tier 0/1 auto-apply; 2/3 queue to the HITL desk.
const GateTier = 2

// TierIrreversible (T3) is the autonomy tier for irreversible / legal / business-critical
// actions — regulatory breach notification, customer comms, mass deletion, risk
// acceptance. The agentic-SMB spec (§3, AGT-3, TS-2) is categorical about T3: the agent
// PREPARES, a named human DECIDES and SIGNS — it MUST NOT execute on an auto/"auto"
// approver, and MUST NOT be eligible for any break-glass / pre-authorized auto-apply that
// a lower tier might later get. Enforced in hitl.Desk (a T3 with no named human approver
// is refused, not applied).
const TierIrreversible = 3

// NeedsApproval reports whether this action must pause for a human (tier-gated).
func (a Action) NeedsApproval() bool { return a.Tier >= GateTier }

// NeedsHumanSignature reports whether this action is irreversible (T3) and therefore must
// carry a named human's recorded sign-off — never an automated apply, ever.
func (a Action) NeedsHumanSignature() bool { return a.Tier >= TierIrreversible }

// ControlState statuses.
const (
	ControlMet       = "met"
	ControlGap       = "gap"
	ControlException = "exception"
)

// ControlState is the GRC system-of-record: one control's live status under one
// framework for one tenant, with the evidence that backs it. Continuously updated by
// the grc layer as findings are emitted — the auditable, lock-in artifact.
type ControlState struct {
	TenantID     string    `json:"tenant_id"`
	Framework    string    `json:"framework"`  // soc2 | iso27001 | dpdp | ...
	ControlID    string    `json:"control_id"` // e.g. CC6.1
	State        string    `json:"state"`      // ControlMet | ControlGap | ControlException
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ThirdPartyApp is one third-party OAuth integration with access to a tenant's identity
// provider (Google Workspace / M365 / Okta) — the SaaS/app inventory a compliance team
// needs (SOC2 vendor management, shadow-IT review), not just the risky ones we flag as
// findings. Refreshed each operate scan from the live OAuth grants.
type ThirdPartyApp struct {
	TenantID   string   `json:"tenant_id"`
	Provider   string   `json:"provider"` // gworkspace | m365 | okta
	AppID      string   `json:"app_id"`   // the app's display name (or client id)
	Scopes     []string `json:"scopes"`
	Users      int      `json:"users"`       // how many users granted it
	AdminScope bool     `json:"admin_scope"` // holds a directory/admin scope (shadow-admin)
	Verified   bool     `json:"verified"`    // publisher-verified by the provider
}

// Incident statuses.
const (
	IncidentOpen     = "open"
	IncidentResolved = "resolved"
)

// Incident is a durable, deduped security issue tracked across monitoring passes — the
// continuous-monitoring system-of-record that raw findings (overwritten every scan) can't
// provide. The detect layer opens one when a finding at/above the severity threshold
// first appears, and resolves it when that issue stops appearing — so the platform can
// say "this critical issue is NEW since the last pass" and "this one is now fixed",
// timestamped. Key is the stable issue identity (rule + cited entity) so the same issue
// re-detected across scans maps to the same incident.
// CERTInStatus is an incident's reporting position against the CERT-In six-hour window
// (Directions of 28 April 2022, Direction (ii)). Computed at read time by internal/certin
// from the incident's timestamps + its opening finding's CERT-In annotation; the type lives
// here (not in internal/certin) so platform.Incident can carry it without an import cycle,
// exactly as SLABreach does.
type CERTInStatus struct {
	DueAt       time.Time `json:"due_at"`   // NoticedAt + 6h
	Reported    bool      `json:"reported"` // a human has filed it
	ReportedAt  time.Time `json:"reported_at,omitzero"`
	Breached    bool      `json:"breached"`     // past due and still not reported
	MinutesLeft int       `json:"minutes_left"` // negative once the window closed
	Categories  []string  `json:"categories"`   // the Annexure I types this falls under (the evidence)
}

type Incident struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Key       string `json:"key"` // stable identity: "<rule_id>|<endpoint>"
	RuleID    string `json:"rule_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`     // IncidentOpen | IncidentResolved
	FindingID string `json:"finding_id"` // the finding that opened it
	// Verification + Confidence are the FP-control signal carried from the finding that opened this
	// incident (§11 hook 10). So an alert shows whether it's a verified exploit, corroborated by ≥2
	// independent tools, or an unconfirmed pattern_match the user should confirm — we never present a
	// low-confidence finding as a confirmed incident (the "no high false positive" rule). Empty/0 when
	// the opening finding carried no quality signal.
	Verification string  `json:"verification,omitempty"`
	Confidence   float64 `json:"confidence,omitempty"`
	// AbsentPasses counts CONSECUTIVE authoritative scans in which this incident's issue did not
	// appear. Reset to 0 the moment it reappears.
	//
	// Resolving on a single absence assumes a scan that does not report a finding proves it is gone.
	// Measured against WAVSEP: dalfox on the same unchanged target found 7 distinct vulnerable cases
	// in one run and 9 in the next — and it SUCCEEDED both times, so nothing was recorded as failed.
	// Four cases flipped between runs. On a single-absence rule each flip resolves a live
	// vulnerability as fixed and reopens it next pass, forever.
	//
	// Distinct from the degraded-pass guard: that covers tools which DIE (Scan.ToolsFailed). This
	// covers tools that finish and simply report different things, which no failure signal catches.
	AbsentPasses int `json:"absent_passes,omitempty"`
	// Attacked marks an incident opened/escalated because the issue is observed under
	// attack in production (a runtime-protection signal, ADR-0007 Phase 0b) — escalated
	// regardless of the severity floor, since a live exploit attempt is itself urgent.
	Attacked bool `json:"attacked,omitempty"`
	// Triage* carry a Detection Skill verdict onto the alert (ADR 0017). That is the whole point of
	// the format: the detection engineer's reasoning travels WITH the alert instead of being
	// rediscovered by whoever is on shift. TriageSkill is "name@digest", so an evidence pack can
	// state exactly which skill version produced the verdict.
	//
	// ANNOTATION ONLY — a verdict never opens or closes an incident. A skill is third-party input,
	// so letting a "benign" verdict silence a real alert would hand an injected skill a mute button
	// on the SOC. The severity floor still decides whether an incident exists; the skill explains it.
	TriageVerdict   string    `json:"triage_verdict,omitempty"`
	TriageRationale string    `json:"triage_rationale,omitempty"`
	TriageSkill     string    `json:"triage_skill,omitempty"`
	OpenedAt        time.Time `json:"opened_at"`
	ResolvedAt      time.Time `json:"resolved_at,omitzero"`
	LedgerRef       string    `json:"ledger_ref,omitempty"`
	// AcknowledgedAt/By record that a human took ownership of the incident (the MDR "I'm on it").
	// An acknowledged incident is never auto-escalated. Zero = unacknowledged.
	AcknowledgedAt time.Time `json:"acknowledged_at,omitzero"`
	AcknowledgedBy string    `json:"acknowledged_by,omitempty"`
	// LastEscalatedAt is when the timed auto-escalation last re-alerted this incident, so it
	// re-pings at most once per AckWindowMins instead of every monitoring pass.
	LastEscalatedAt time.Time `json:"last_escalated_at,omitzero"`
	// SLABreach is a TRANSIENT, read-time annotation (the incident's state vs. the tenant's SLA
	// policy) — populated by the API when returning incidents, NEVER persisted. nil = not tracked.
	SLABreach *SLABreach `json:"sla_breach,omitempty"`
	// CertIn is the transient CERT-In six-hour reporting position (read-time only, never
	// persisted — like SLABreach). nil unless the opening finding is a CERT-In Annexure I
	// reportable category (§10: no annotation, no reporting duty).
	CertIn *CERTInStatus `json:"certin,omitempty"`
	// CertInReportedAt / By are PERSISTED: when a named human filed the CERT-In report and
	// who. A filing discharges the six-hour duty (even if late), so this is what stops the
	// breach clock — the CERT-In analogue of AcknowledgedAt.
	CertInReportedAt time.Time `json:"certin_reported_at,omitzero"`
	CertInReportedBy string    `json:"certin_reported_by,omitempty"`
	// BlastRadius is a TRANSIENT, read-time impact annotation: whether this incident's finding sits on a
	// cross-surface chain reaching a crown jewel (how big it can get). Computed by the API from the
	// correlate chains when returning incidents, NEVER persisted. nil = not on a crown-jewel chain.
	BlastRadius *BlastRadius `json:"blast_radius,omitempty"`
	// Onset is a TRANSIENT, read-time annotation naming WHEN the underlying state changed, read from the
	// estate timeline. Same pattern as SLABreach/BlastRadius: computed on return, never persisted.
	//
	// It is the difference between two very different alerts that otherwise look identical. "This bucket
	// is public" is a fact; "this bucket became public forty minutes ago" is an incident. The first gets
	// triaged next week, the second gets someone's attention now — and a responder currently has to go
	// and find out which one they are holding. nil = the timeline has nothing to say about it.
	Onset *Onset `json:"onset,omitempty"`
	// KEV marks an incident whose opening finding carries a CISA KEV listing
	// (exploited in the wild). Stamped in detect.Reconcile from the finding's
	// ThreatIntel.KEV.Listed; drives the SLAPolicy.KEVResolveHours override.
	KEV bool `json:"kev,omitempty"`
	// Ransomware marks an incident whose CVE CISA records as used in RANSOMWARE
	// campaigns (knownRansomwareCampaignUse). Strictly stronger than KEV and kept
	// separate from it for that reason; drives SLAPolicy.RansomwareResolveHours.
	Ransomware bool `json:"ransomware,omitempty"`
	// KEVDueAt is CISA's OWN published remediation deadline for the CVE — an
	// absolute date, deliberately not a duration, so rediscovering an old KEV CVE
	// cannot restart a clock the authority already ran out.
	//
	// OMITZERO, not omitempty: most incidents have no KEV CVE behind them and therefore no
	// deadline, and "no deadline" must serialize as ABSENT. `omitempty` has no effect on a
	// struct, so this shipped `"kev_due_at":"0001-01-01T00:00:00Z"` on every incident. The
	// frontend guard was written against the contract the tag advertises (`if (!i.kev_due_at)
	// return null`), which a non-empty string passes, so the queue told the customer a CISA
	// federal remediation deadline had PASSED — on incidents with no CVE at all. Asserting a
	// government deadline nobody set, and that the reader is already late for it, is the §10
	// grounding failure in its most alarming form.
	KEVDueAt time.Time `json:"kev_due_at,omitzero"`
}

// Onset is when the state behind an incident actually changed.
type Onset struct {
	// At is the capture in which the change was first observed.
	At time.Time `json:"at"`
	// What happened, in the responder's terms ("became internet-facing").
	What string `json:"what"`
	// ResourceID is what changed.
	ResourceID string `json:"resource_id"`
	// Note carries the honest limit: we observe BETWEEN captures, so At is when we first SAW it, not
	// necessarily when it happened. A responder reconstructing a timeline must not read one as the other.
	Note string `json:"note,omitempty"`
}

// Acknowledged reports whether a human has taken ownership of the incident.
func (i Incident) Acknowledged() bool { return !i.AcknowledgedAt.IsZero() }

// Overdue reports whether an OPEN, UNACKNOWLEDGED incident has gone past the ack window and is due
// for a timed auto-escalation re-alert. ackWindowMins ≤ 0 disables timed escalation. It re-pings at
// most once per window (tracked by LastEscalatedAt). now is injected so it's testable.
func (i Incident) Overdue(ackWindowMins int, now time.Time) bool {
	if ackWindowMins <= 0 || i.Status != IncidentOpen || i.Acknowledged() {
		return false
	}
	window := time.Duration(ackWindowMins) * time.Minute
	if now.Sub(i.OpenedAt) < window {
		return false // still within the first response window
	}
	// re-ping only if we haven't escalated yet, or the last escalation is itself a window old
	return i.LastEscalatedAt.IsZero() || now.Sub(i.LastEscalatedAt) >= window
}

// Risk treatment decisions (the vCISO judgment the agent cannot make on its own).
const (
	RiskTreatmentAccept   = "accept"   // accept the risk as-is (residual risk owned)
	RiskTreatmentMitigate = "mitigate" // reduce via a control / remediation
	RiskTreatmentTransfer = "transfer" // shift to a third party (insurance, vendor)
	RiskTreatmentAvoid    = "avoid"    // eliminate by removing the exposed function
)

// Risk statuses.
const (
	RiskOpen     = "open"     // identified, no human treatment decision yet
	RiskAccepted = "accepted" // a named human accepted the residual risk
	RiskTreating = "treating" // mitigation/transfer/avoidance in progress
	RiskClosed   = "closed"   // resolved or no longer applicable
)

// Risk is a risk-register entry — the core vCISO/GRC artifact a security consultant
// maintains. The engine can PROPOSE a candidate risk from a real finding (grounded: it
// cites the finding ids), but the TREATMENT DECISION is a human judgment call: only a
// named person can accept/transfer/avoid residual risk, and that decision is signed into
// the ledger (DecidedBy/At/LedgerRef). Likelihood and Impact are 1–5; Score = L×I (1–25).
type Risk struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category,omitempty"` // e.g. "Access control", "Vendor", "Data"
	Likelihood  int      `json:"likelihood"`         // 1–5
	Impact      int      `json:"impact"`             // 1–5
	Treatment   string   `json:"treatment,omitempty"`
	Status      string   `json:"status"`
	Owner       string   `json:"owner,omitempty"`     // the accountable human
	Rationale   string   `json:"rationale,omitempty"` // why this treatment (the human's judgment)
	FindingIDs  []string `json:"finding_ids,omitempty"`
	Proposed    bool     `json:"proposed,omitempty"` // true = agent-seeded candidate, awaiting human triage
	// Capacity + Firm record WHO the deciding human works for (resolved from the practitioner roster):
	// internal | msp | managed, and their firm. Makes the decision honest about who accepted the risk
	// and in what capacity (the tenant's own owner vs the MSP's vCISO vs our managed expert).
	Capacity string `json:"capacity,omitempty"`
	Firm     string `json:"firm,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	DecidedBy string    `json:"decided_by,omitempty"`
	LedgerRef string    `json:"ledger_ref,omitempty"`
}

// Score is the inherent risk score, Likelihood × Impact (1–25). Clamped to the 1–5 range
// per factor so a malformed input can't produce a nonsense score.
func (r Risk) Score() int { return clamp15(r.Likelihood) * clamp15(r.Impact) }

// Level buckets the score into a human label: low (<6), medium (<12), high (<20), critical (≥20).
func (r Risk) Level() string {
	switch s := r.Score(); {
	case s >= 20:
		return "critical"
	case s >= 12:
		return "high"
	case s >= 6:
		return "medium"
	default:
		return "low"
	}
}

// AIAnalysis is a PERSISTED run of the AI Security Engineer over a tenant's estate — the deliverable the L2
// Lead produced (whole-estate "Triage", a per-issue "Investigate", or a cloud attack-path investigation).
// It is stored so the SMB user's analysis SURVIVES navigation: run it once, read it later, without re-spending
// the LLM. Grounded (§10): it records only what the agent actually produced (summary + reports + model +
// cost); it asserts nothing the run didn't. The ID is deterministic (Kind + ":" + Scope) so a fresh run
// OVERWRITES the prior one for that scope — the store holds the LATEST analysis per scope, bounded by design.
type AIAnalysis struct {
	ID          string     `json:"id"` // deterministic: Kind ":" Scope (so a re-run overwrites)
	TenantID    string     `json:"tenant_id"`
	Kind        string     `json:"kind"`                  // "triage" (whole estate) | "investigate" (one issue) | "cloud"
	Scope       string     `json:"scope,omitempty"`       // investigate: the issue key; cloud: the target; triage: ""
	Title       string     `json:"title,omitempty"`       // a short human label for the scope
	Summary     string     `json:"summary"`               // the agent's executive summary
	Recommends  string     `json:"recommends,omitempty"`  // "what to do next" — the FIX narrative (must persist too)
	Methodology string     `json:"methodology,omitempty"` // "how we looked" — the agent's approach
	Reports     []AIReport `json:"reports,omitempty"`     // the prioritized per-issue reports
	Model       string     `json:"model,omitempty"`       // which model produced it (honest provenance)
	Iterations  int        `json:"iterations,omitempty"`
	CostUSD     float64    `json:"cost_usd,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AIReport is one prioritized item within an AIAnalysis (a per-issue narrative).
type AIReport struct {
	Title    string `json:"title"`
	Severity string `json:"severity,omitempty"`
	Body     string `json:"body,omitempty"`
}

// AIAnalysisID builds the deterministic id for a (kind, scope) so re-runs overwrite the prior analysis.
func AIAnalysisID(kind, scope string) string { return kind + ":" + scope }

// ComplianceSnapshot is one timestamped point on a framework's CONTINUOUS-EVIDENCE timeline — the
// answer to "was this control Met across the whole audit window?", which the point-in-time EvidencePack
// (grc.go) can't show. Unlike AIAnalysis it is APPEND-ONLY (a unique id per capture), so the store keeps
// the history an auditor reads as continuity proof. StateHash captures the per-control states so a
// capture is skipped when nothing changed (see grc.CaptureEvidenceSnapshot) — the history stays
// meaningful without per-monitoring-pass bloat. Grounded (§10): the counts come from real ControlState.
// EvalRun is one recorded evaluation of the tenant's own eval suite — append-only, so a trend can
// exist at all. SuiteHash is what makes the trend honest rather than merely available: two runs are
// comparable ONLY if they graded the same case set the same way (internal/tenanteval.TrendOf).
type EvalRun struct {
	ID        string         `json:"id"` // append-only: RFC3339Nano of the run
	TenantID  string         `json:"tenant_id"`
	RanAt     time.Time      `json:"ran_at"`
	Cases     int            `json:"cases"`
	Passed    int            `json:"passed"`
	SuiteHash string         `json:"suite_hash"`
	BySource  map[string]int `json:"by_source,omitempty"`
	// Arm records WHICH grader produced this score: the deterministic filter, or a model. Without
	// it the two interleave in one history and a trend compares a model's score against the
	// filter's, which is not a comparison at all. Empty means substrate — runs recorded before this
	// field existed were all substrate runs.
	Arm string `json:"arm,omitempty"`
	// Model names the model that produced a model-arm score. A score that moved because the
	// customer switched models is a different fact from one that moved on its own, and without the
	// name the two are indistinguishable.
	Model string `json:"model,omitempty"`
}

type ComplianceSnapshot struct {
	ID            string    `json:"id"` // append-only: Framework ":" RFC3339Nano capture time
	TenantID      string    `json:"tenant_id"`
	Framework     string    `json:"framework"`
	CapturedAt    time.Time `json:"captured_at"`
	TotalControls int       `json:"total_controls"`
	MetControls   int       `json:"met_controls"`
	GapControls   int       `json:"gap_controls"`
	StateHash     string    `json:"state_hash"` // sha256 of the sorted per-control states — change detection
	FullyMet      bool      `json:"fully_met"`  // no gaps at capture time — the "audit-ready" bit for this instant
}

func clamp15(n int) int {
	if n < 1 {
		return 1
	}
	if n > 5 {
		return 5
	}
	return n
}

// Audit-engagement statuses (the SOC2/ISO audit the tenant runs WITH an external auditor).
const (
	AuditPlanning  = "planning"  // scope + auditor named, evidence being assembled
	AuditFieldwork = "fieldwork" // the auditor is reviewing evidence + attesting controls
	AuditIssued    = "issued"    // the auditor has issued the report
)

// Audit types.
const (
	AuditTypeI  = "type_i"  // controls designed correctly at a point in time
	AuditTypeII = "type_ii" // controls operated effectively over a period
)

// Control-attestation verdicts (the independent auditor's call — NOT the engine's).
const (
	AttestPending   = "pending"
	AttestPassed    = "passed"
	AttestException = "exception"
)

// ControlAttestation is the independent auditor's verdict on one control — the legal layer the tool
// cannot replace. The engine assembles the evidence; a NAMED human auditor reviews it and attests.
type ControlAttestation struct {
	Framework  string    `json:"framework"`
	ControlID  string    `json:"control_id"`
	Verdict    string    `json:"verdict"` // pending | passed | exception
	Note       string    `json:"note,omitempty"`
	AttestedBy string    `json:"attested_by,omitempty"` // the external auditor, by name
	AttestedAt time.Time `json:"attested_at,omitzero"`
	Capacity   string    `json:"capacity,omitempty"` // who the attester works for (resolved from roster)
	Firm       string    `json:"firm,omitempty"`
}

// AuditEngagement is a SOC2/ISO (etc.) audit the tenant runs with an EXTERNAL auditor. The product is
// "audit-ready, not the audit": it pre-populates the controls to be attested from the tenant's posture
// and tracks the engagement, but the attestation itself is an independent licensed human's — recorded
// here per control, signed into the ledger. AuditorName/Firm/Email name that human.
type AuditEngagement struct {
	ID           string               `json:"id"`
	TenantID     string               `json:"tenant_id"`
	Framework    string               `json:"framework"`
	AuditType    string               `json:"audit_type"` // type_i | type_ii
	PeriodStart  time.Time            `json:"period_start,omitzero"`
	PeriodEnd    time.Time            `json:"period_end,omitzero"`
	AuditorName  string               `json:"auditor_name,omitempty"`
	AuditorFirm  string               `json:"auditor_firm,omitempty"`
	AuditorEmail string               `json:"auditor_email,omitempty"`
	Status       string               `json:"status"`
	Attestations []ControlAttestation `json:"attestations,omitempty"`
	CreatedAt    time.Time            `json:"created_at"`
	IssuedAt     time.Time            `json:"issued_at,omitzero"`
	LedgerRef    string               `json:"ledger_ref,omitempty"`
}

// Progress reports how many controls the auditor has attested (passed or exception) out of the total.
func (a AuditEngagement) Progress() (attested, total int) {
	total = len(a.Attestations)
	for _, c := range a.Attestations {
		if c.Verdict == AttestPassed || c.Verdict == AttestException {
			attested++
		}
	}
	return attested, total
}

// Policy statuses — a security policy is the vCISO/program deliverable a consultant writes and the
// owner adopts. Draft until a named owner publishes it (the HITL judgment act).
const (
	PolicyDraft     = "draft"
	PolicyPublished = "published"
)

// PolicyAck records that a named team member acknowledged a published policy (the "everyone has read
// and accepted" evidence auditors ask for).
type PolicyAck struct {
	User    string    `json:"user"`
	AckedAt time.Time `json:"acked_at"`
}

// Policy is one security policy in the tenant's program. The engine can seed the standard policy set
// (industry-standard templates, grounded — not invented), but ADOPTING/PUBLISHING one is a named
// human's call, and each team member's acknowledgment is recorded. Published policies + their acks
// are the program evidence a SOC 2 audit expects.
type Policy struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	Name        string      `json:"name"`
	Category    string      `json:"category,omitempty"` // e.g. "Access Control", "Incident Response"
	Summary     string      `json:"summary,omitempty"`
	Status      string      `json:"status"`
	Owner       string      `json:"owner,omitempty"`    // the accountable human
	Capacity    string      `json:"capacity,omitempty"` // who the publishing owner works for (resolved from roster)
	Firm        string      `json:"firm,omitempty"`
	Version     int         `json:"version"`
	Acks        []PolicyAck `json:"acks,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	PublishedAt time.Time   `json:"published_at,omitzero"`
	LedgerRef   string      `json:"ledger_ref,omitempty"`
}

// AckedBy reports whether the given user has acknowledged this policy.
func (p Policy) AckedBy(user string) bool {
	for _, a := range p.Acks {
		if a.User == user {
			return true
		}
	}
	return false
}

// ReviewRequest statuses.
const (
	ReviewOpen     = "open"
	ReviewResolved = "resolved"
)

// ReviewRequest is a human-expert review the tenant asks for on a finding or a
// IgnoreRule suppresses a unified issue from the active list — the issue-lifecycle
// "ignore / accept-risk / false-positive" control. Keyed by the issue's dedup key
// (so it survives re-scans). Carries who suppressed it, when, and why, so the
// suppression is itself auditable (and reversible via un-ignore).
type IgnoreRule struct {
	TenantID string    `json:"tenant_id"`
	IssueKey string    `json:"issue_key"`
	Reason   string    `json:"reason"`         // "false_positive" | "accepted_risk" | free text
	Note     string    `json:"note,omitempty"` // optional human explanation
	By       string    `json:"by,omitempty"`   // who suppressed it
	At       time.Time `json:"at"`
}

// Feedback is a person's JUDGEMENT about an issue, and it is deliberately not an
// IgnoreRule.
//
// An IgnoreRule is an ACTION — hide this from my list. Feedback is an OPINION — here is
// what I think of it. Conflating them costs both directions: a customer who thinks a
// finding is real but poorly evidenced has no way to say so without hiding it, and a
// customer who hides something for their own reasons is read as disputing it.
//
// The field that does not exist anywhere else is Evidence. Every other signal the
// product collects answers "did we RANK this right"; this one answers "was our PROOF
// good enough", which is the question a security team stakes its reputation on and the
// only one whose answer can improve the verifier rather than the filter. The machine
// half of that signal comes free from re-attack disagreements (retest.ApplyReattack);
// this is the human half, for the far larger set of findings nobody re-attacks.
type Feedback struct {
	TenantID string `json:"tenant_id"`
	// IssueKey is the crossdetect.DedupKey of the issue. Keyed the same way as an
	// IgnoreRule so the two can be read together, and computed by the same function that
	// assigned it — never rebuilt by hand.
	IssueKey string `json:"issue_key"`
	// Verdict is what the person thinks of the finding itself.
	Verdict string `json:"verdict"` // FeedbackReal | FeedbackFalsePositive | FeedbackUnclear
	// Evidence is what they think of our PROOF, and it is independent of Verdict: "yes
	// this is real, and no you did not show me why" is the most useful thing a customer
	// can say, and it is unsayable if the two collapse into one field.
	Evidence string    `json:"evidence,omitempty"` // "" | EvidenceSufficient | EvidenceInsufficient
	Note     string    `json:"note,omitempty"`
	By       string    `json:"by,omitempty"`
	At       time.Time `json:"at"`
}

// Feedback verdicts about the finding.
const (
	FeedbackReal          = "real"           // the finding is correct
	FeedbackFalsePositive = "false_positive" // the finding is wrong
	// FeedbackUnclear means the reader could not tell. It is recorded rather than
	// discarded because "I could not understand this finding" is a defect in the
	// finding, not an absence of opinion — and it is invisible if the only options
	// are agree and disagree.
	FeedbackUnclear = "unclear"
)

// Feedback verdicts about our evidence.
const (
	EvidenceSufficient   = "sufficient"
	EvidenceInsufficient = "insufficient"
)

// ValidFeedbackVerdict reports whether v is a verdict we accept. An unrecognised verdict
// is REFUSED rather than stored as free text: a corpus whose labels are open-ended cannot
// be counted, and a label nobody defined cannot be learned from.
func ValidFeedbackVerdict(v string) bool {
	switch v {
	case FeedbackReal, FeedbackFalsePositive, FeedbackUnclear:
		return true
	}
	return false
}

// ValidFeedbackEvidence reports whether e is an accepted evidence verdict. Empty is
// valid and means "no opinion offered" — distinct from either judgement.
func ValidFeedbackEvidence(e string) bool {
	switch e {
	case "", EvidenceSufficient, EvidenceInsufficient:
		return true
	}
	return false
}

// ExclusionRule is a PATTERN-based noise filter (Aikido "custom rules": exclude
// specific paths, packages, conditions). Unlike IgnoreRule (which suppresses one
// exact issue by its dedup key), an ExclusionRule drops every finding whose chosen
// attribute matches a glob — applied before findings are unified, so excluded noise
// disappears from the issue list entirely. Carries who/why/when, so it's auditable
// and reversible like a suppression.
type ExclusionRule struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id"`
	Field    string    `json:"field"`   // rule_id | package | path | cve | any
	Pattern  string    `json:"pattern"` // glob with '*' wildcards (case-insensitive), e.g. "trivy::CVE-2021-*", "lodash", "*/test/*"
	Reason   string    `json:"reason,omitempty"`
	Note     string    `json:"note,omitempty"`
	By       string    `json:"by,omitempty"`
	At       time.Time `json:"at"`
}

// Exclusion field constants (the attribute an ExclusionRule.Pattern matches against).
const (
	ExclByRule    = "rule_id"
	ExclByPackage = "package"
	ExclByPath    = "path"
	ExclByCVE     = "cve"
	ExclByAny     = "any"
)

// RuntimeEvent is a single attack observation from an in-app firewall / RASP sensor
// (Runtime Protection, ADR-0007 Phase 0 — e.g. the OSS "Zen" firewall running in the
// customer's app). tsengine consumes it as a signal; it does NOT block — the sensor
// does. The platform's value is correlating these with scan-time findings: a finding
// on an endpoint that is ALSO being attacked in production is observed-in-the-wild,
// the strongest exploitability signal there is.
type RuntimeEvent struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	App        string `json:"app,omitempty"`         // the app/service that reported it
	AttackKind string `json:"attack_kind,omitempty"` // sql_injection | ssrf | path_traversal | xss | ...
	Endpoint   string `json:"endpoint,omitempty"`    // the route the attack hit
	Sink       string `json:"sink,omitempty"`        // the dangerous sink reached, if known
	SourceIP   string `json:"source_ip,omitempty"`   // the attacker IP (informational)
	Blocked    bool   `json:"blocked"`               // did the sensor block it (vs monitor-only)
	// Marker is a token the sensor observed in the request, when it captures one. Optional: most
	// sensors report only the shape of an attack. When present it is the STRONG join for detection
	// validation (ADR 0027 S1) — an exact tie between one alert and the probe that caused it, rather
	// than an inference from endpoint, class and timing.
	Marker     string    `json:"marker,omitempty"`
	Source     string    `json:"source,omitempty"` // sensor name (e.g. "zen")
	OccurredAt time.Time `json:"occurred_at"`
}

// proposed action — the "AI + a human" trust model SMB security buyers expect
// (a managed-SOC / vCISO escalation). It is request-and-resolve, tenant-scoped,
// and signed into the ledger like every other decision (§18.2 inv. 4). The agent
// keeps working; this is the deliberate human-in-the-loop escape hatch.
type ReviewRequest struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Subject    string    `json:"subject"`    // "finding" | "action"
	SubjectID  string    `json:"subject_id"` // the finding/action id under review
	Note       string    `json:"note"`       // why the tenant wants an expert to look
	Requester  string    `json:"requester,omitempty"`
	Status     string    `json:"status"` // ReviewOpen | ReviewResolved
	Resolution string    `json:"resolution,omitempty"`
	Reviewer   string    `json:"reviewer,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ResolvedAt time.Time `json:"resolved_at,omitzero"`
}

// ReadinessAttestation is a named human's answer to a security practice that cannot be scanned for.
//
// Both answers are recorded, including "not in place" — a record that only keeps the yes is one
// nobody should trust, and knowing a gap is acknowledged is more useful than not knowing at all.
type ReadinessAttestation struct {
	InPlace bool   `json:"in_place"`
	By      string `json:"by"`
	At      string `json:"at"`
	Note    string `json:"note,omitempty"`
}

// QuestionnaireAttestation is a named human's answer to a security-questionnaire question that
// cannot be scanned for. Same shape as ReadinessAttestation and deliberately its own type: these
// answers are published to a buyer through the Trust Center, so a change to one must not silently
// change what the other asserts to a third party.
//
// InPlace false is a real, useful answer — "no, we do not carry cyber insurance" is what the buyer
// asked — so it is recorded rather than treated as an absent answer.
type QuestionnaireAttestation struct {
	InPlace bool   `json:"in_place"`
	By      string `json:"by"`
	At      string `json:"at"`
	Note    string `json:"note,omitempty"`
}

// EpisodeRecord is one scored agent run, persisted so the corpus can be QUERIED:
// which runs moved posture, at what cost, under whose consent (ADR 0018 §4).
//
// It carries the SCORE, not the trajectory. The step trail already lives in the
// ledger's own signed, tamper-evident export, and copying it into a JSON-blob row per
// episode would duplicate the one artifact that is already attested — so LedgerSHA
// references it rather than restating it. The consequence is worth saying plainly: this
// row is what makes the corpus searchable, and the trajectory it points at is the
// training payload. A row alone is not a training example.
type EpisodeRecord struct {
	ID       string `json:"id"` // append-only: RFC3339Nano of the run
	TenantID string `json:"tenant_id"`
	// AgentKind is the ledger's own vocabulary (webagent | cloudagent | llmredteam).
	AgentKind string `json:"agent_kind"`
	// Scope is what was censused, and it is what makes two episodes comparable —
	// ledger.Diff refuses a mismatch, so a trend over episodes has to filter by it.
	Scope       string    `json:"scope"`
	RanAt       time.Time `json:"ran_at"`
	CompletedAt time.Time `json:"completed_at,omitzero"`
	// LedgerSHA is the attestation hash of the signed trajectory this scores. Empty
	// when the run produced no signed ledger, which is honest rather than fatal: the
	// score still stands, it simply cannot be replayed back to the steps.
	LedgerSHA string `json:"ledger_sha,omitempty"`

	// Delta is the measured posture change, nil when it could not be computed. Unscored
	// then says why — a nil delta with no reason is indistinguishable from a run that
	// changed nothing, and those are opposite facts.
	Delta    *ledger.SecurityStateDelta `json:"delta,omitempty"`
	Unscored string                     `json:"unscored,omitempty"`

	Cost         ledger.Cost     `json:"cost"`
	Training     ledger.Training `json:"training"`
	Difficulty   string          `json:"difficulty,omitempty"`
	AgentVersion string          `json:"agent_version,omitempty"`
	Model        string          `json:"model,omitempty"`

	// The four independent status axes, each the string form of the vocabulary its own
	// package owns. Kept apart on purpose — see ledger.Episode.
	StopReason   string `json:"stop_reason,omitempty"`
	Verification string `json:"verification,omitempty"`
	FixStatus    string `json:"fix_status,omitempty"`
	HumanVerdict string `json:"human_verdict,omitempty"`

	// Decisions is how many commitments the run made; Verified how many of those were
	// verified. Verified is the denominator of cost-per-outcome, so it is stored rather
	// than recomputed later against findings that will have moved on.
	Decisions int `json:"decisions"`
	Verified  int `json:"verified"`
}

// NewEpisodeRecord flattens a ledger.Episode into its persistable score.
//
// It reads what the episode actually holds and asserts nothing beyond it: a nil ledger
// yields an empty AgentKind rather than a guess, and an unsigned ledger yields an empty
// LedgerSHA rather than a fabricated one.
func NewEpisodeRecord(tenantID, scope string, e *ledger.Episode, verified int) EpisodeRecord {
	if e == nil {
		return EpisodeRecord{TenantID: tenantID, Scope: scope}
	}
	rec := EpisodeRecord{
		TenantID: tenantID, Scope: scope,
		Delta: e.Delta, Unscored: e.Unscored,
		Cost: e.Cost, Training: e.Training,
		Difficulty: e.Difficulty, AgentVersion: e.AgentVersion, Model: e.Model,
		StopReason: e.StopReason, Verification: e.Verification,
		FixStatus: e.FixStatus, HumanVerdict: e.HumanVerdict,
		Verified: verified,
	}
	if l := e.Ledger; l != nil {
		rec.AgentKind = l.AgentKind
		rec.RanAt, rec.CompletedAt = l.StartedAt, l.CompletedAt
		rec.Decisions = len(l.Decisions)
		if l.Attestation != nil {
			rec.LedgerSHA = l.Attestation.SHA256
		}
	}
	if rec.RanAt.IsZero() && e.Before != nil {
		rec.RanAt = e.Before.At
	}
	if rec.CompletedAt.IsZero() && e.After != nil {
		rec.CompletedAt = e.After.At
	}
	if rec.ID == "" && !rec.RanAt.IsZero() {
		rec.ID = rec.RanAt.UTC().Format(time.RFC3339Nano)
	}
	return rec
}

// EpisodeStats rolls a set of episodes into the numbers the ADR makes first-class:
// spend per verified outcome, and how much of the corpus is actually usable.
type EpisodeStats struct {
	Episodes int `json:"episodes"`
	// Scored is how many carried a computable delta. The gap between Episodes and
	// Scored is not noise — it is the share of runs whose effect nobody can measure,
	// and it belongs on the same screen as the numbers derived from the rest.
	Scored    int     `json:"scored"`
	Trainable int     `json:"trainable"`
	CostUSD   float64 `json:"cost_usd"`
	Verified  int     `json:"verified"`
	// CostPerVerified is reported only when something was verified — see HasCostPer.
	// Zero verified outcomes has no ratio, and folding a sentinel into a fleet average
	// would rank the agent that finds nothing as the most efficient one.
	CostPerVerified float64 `json:"cost_per_verified,omitempty"`
	HasCostPer      bool    `json:"has_cost_per_verified"`
	// Opened and Closed are summed across the corpus's scored episodes. Closed counts
	// issues that STOPPED APPEARING and is not a fix count — see SecurityStateDelta.
	Opened int `json:"opened"`
	Closed int `json:"closed"`
}

// SummarizeEpisodes computes EpisodeStats over a corpus slice.
func SummarizeEpisodes(eps []EpisodeRecord) EpisodeStats {
	var s EpisodeStats
	for _, e := range eps {
		s.Episodes++
		s.CostUSD += e.Cost.USD
		s.Verified += e.Verified
		if e.Training.Consented {
			s.Trainable++
		}
		if e.Delta != nil {
			s.Scored++
			s.Opened += len(e.Delta.Opened)
			s.Closed += len(e.Delta.Closed)
		}
	}
	if s.Verified > 0 {
		s.CostPerVerified, s.HasCostPer = s.CostUSD/float64(s.Verified), true
	}
	return s
}

// TrainingConsent is a tenant's standing answer to "may our runs improve the product".
//
// Turning it OFF stops future episodes being stamped as consented. It does NOT rewrite
// episodes already recorded, and the product must not imply otherwise: those were
// collected under an agreement that was real at the time, and silently relabelling them
// would make the record say something that was never true. Withdrawal of consent for
// data already used is a deletion request, which is a different operation with a
// different audit trail — not a boolean flip.
type TrainingConsent struct {
	Consented bool      `json:"consented"`
	By        string    `json:"by,omitempty"`
	At        time.Time `json:"at,omitzero"`
	// Statement is the text the customer actually agreed to, verbatim. An auditor should
	// read what was consented to, not our later summary of it — the same discipline
	// pentest.RoE applies to active-exploitation consent.
	Statement string `json:"statement,omitempty"`
}

// FixEfficacy is the measured track record of one kind of remediation against one kind of finding.
// Transient: computed at read time from the tenant's own verified actions, never stored.
type FixEfficacy struct {
	// Closed / NotClosed are applications that actually settled either way.
	Closed    int `json:"closed"`
	NotClosed int `json:"not_closed"`
	// Unproven counts applications whose re-scan said gone but was not accepted as confirmation
	// (ADR 0025 F1). Excluded from the rate — counting "we do not know" as a success is the
	// overclaim F1 exists to prevent — and reported so the reader can see the sample is smaller
	// than the number of applications.
	Unproven int `json:"unproven,omitempty"`
	// Muted reports that a track record EXISTS but cannot be scored, because too few applications
	// were ever confirmed either way. Distinct from absence: "we cannot judge this yet, and here is
	// why" is a different statement from "this remediation has no history", and rendering the first
	// as the second is the more comfortable of the two.
	Muted bool `json:"muted,omitempty"`
}

// maxVerificationHistory bounds the append-only log. Appends are change-only, so reaching this needs
// dozens of genuine verdict FLIPS on one action — pathological, not routine. The oldest entries are
// dropped at that point, which is a real (if remote) loss of an early contradiction; it is preferred
// over an unbounded row, and anything that noisy has told us what we needed long before entry 32.
const maxVerificationHistory = 32

// RecordVerification sets the current verdict AND appends it to the history when it is materially
// different from the last one.
//
// "Materially different" is (status, disagreement, rescan-said-fixed) — the tuple fieldevidence reads.
// Re-recording an unchanged verdict every monitoring pass would inflate the corpus with duplicates of
// one event, which is the mirror of the erasure bug: one action out-voting the estate instead of
// vanishing from it.
func (a *Action) RecordVerification(v FixVerification) {
	a.Verification = &v
	if n := len(a.VerificationHistory); n > 0 {
		last := a.VerificationHistory[n-1]
		if last.Status == v.Status && last.Disagreement == v.Disagreement &&
			last.RescanSaidFixed == v.RescanSaidFixed {
			return
		}
	}
	a.VerificationHistory = append(a.VerificationHistory, v)
	if len(a.VerificationHistory) > maxVerificationHistory {
		a.VerificationHistory = a.VerificationHistory[len(a.VerificationHistory)-maxVerificationHistory:]
	}
}

// ExposureObjective is the stated target a tenant's exposure trend is graded against (ADR 0028 G3).
//
// It mirrors internal/exposuretrend.Objective rather than importing it, for the same reason every
// other policy on Tenant is defined here: pkg/platform is the domain model and must not depend on an
// internal analysis package. The API converts between them at the boundary, and a test asserts the
// two shapes stay in step — a mirror that drifts silently would grade against a target the customer
// did not set.
type ExposureObjective struct {
	// Declared records that a human set this. Explicit, never inferred from the values: "close at
	// least as much as opens" is NetPerWindow 0, the most natural target in the product, and deriving
	// declaredness from non-zero fields made it indistinguishable from having no objective at all.
	Declared bool `json:"declared"`
	// WindowDays is the period the target applies over; 0 = the whole series.
	WindowDays int `json:"window_days,omitempty"`
	// NetPerWindow is the required closed-minus-opened over the window.
	NetPerWindow int `json:"net_per_window"`
	// MinConfirmedFixed is the required count of RE-TEST-PROVEN closures. 0 disables the clause.
	MinConfirmedFixed int `json:"min_confirmed_fixed,omitempty"`
}

// BusinessService is one named business service and the assets that carry it (ADR 0028 G2).
//
// Declared by the customer, never inferred: which assets serve checkout is a fact about their
// architecture that no scan can discover, and guessing it would route the wrong team to the wrong
// incident — worse than leaving it unmapped.
type BusinessService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Criticality is the business dependency: critical | high | medium | low. Orders the view.
	Criticality string `json:"criticality,omitempty"`
	// Owner is the team or person accountable for this service — who gets paged, not who accepted a
	// risk (that is Risk.Owner, a different question).
	Owner string `json:"owner,omitempty"`
	// AssetIDs are the assets that carry it. An id that no longer resolves is skipped rather than
	// counted, because a dangling reference is not evidence of anything.
	AssetIDs []string `json:"asset_ids,omitempty"`
}
