package platform

import "strings"

// AIMode is how much AI a tenant has CHOSEN to run.
//
// # Why this is a customer control and not just a plan flag
//
// Three different things decide whether an agent runs, and conflating them is how a product becomes
// untrustworthy:
//
//	Plan          what they are ENTITLED to buy          (commercial)
//	AIMode        what they have CHOSEN to run           (preference)  ← this type
//	AgentsHalted  an emergency freeze on everything      (safety)
//
// A tenant entitled to both agents may deliberately run deterministic-only, and the reasons are real
// at the seed/Series-A stage we serve: predictable cost, a trust ramp (watch the deterministic engine
// for a month before letting a model propose changes to your repo), or a policy position about
// sending source to a third-party model. A product that cannot express "not yet" forces that customer
// to choose between all of it and none of it.
//
// # It gates the tenant's OWN key too, and that is deliberate
//
// The economic gate (plan → operator budget) exists to protect OUR spend, so it correctly ignores a
// tenant's own key. THIS gate is different: it is the customer's own instruction about what may run.
// Someone who says "deterministic only" while holding a configured key means it — they are not asking
// us to spend their money instead of ours. So AIMode is checked before both paths.
//
// # Off must be honest, not silently degraded
//
// When a mode is off, the surfaces that would have used it say what is not running and why, rather
// than quietly returning thinner results. A user who turned something off should see that reflected;
// a user who never turned it on should be told what they are missing. Silent degradation is how a
// customer concludes the product is weak when they simply have it switched off.
type AIMode string

const (
	// AIModeUnset means the tenant has expressed no preference. Resolves to whatever the plan allows,
	// so existing tenants keep today's behaviour exactly.
	AIModeUnset AIMode = ""
	// AIModeDeterministic runs the scanners, correlation, enrichment, compliance and plain-English
	// explanations — everything that costs no tokens. Explicitly a FULL product, not a crippled one:
	// the explain layer is model-free precisely so this mode is readable rather than raw.
	AIModeDeterministic AIMode = "deterministic"
	// AIModeEngineer adds the AI Security Engineer: triage, prioritisation, fix proposals, chain
	// narrative. Not the pentester.
	AIModeEngineer AIMode = "engineer"
	// AIModeFull adds the AI Pentester on top: exploitation, proof, re-attack verification.
	AIModeFull AIMode = "full"
)

// NormalizeAIMode maps a raw string to a canonical mode. Unknown input resolves to Unset (plan
// default) rather than to an arbitrary tier — guessing on a control the customer set is worse than
// falling back to what they are entitled to.
func NormalizeAIMode(s string) AIMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(AIModeDeterministic), "off", "none", "deterministic_only":
		return AIModeDeterministic
	case string(AIModeEngineer), "security_engineer", "defense":
		return AIModeEngineer
	case string(AIModeFull), "engineer+pentester", "all", "both":
		return AIModeFull
	default:
		return AIModeUnset
	}
}

// ValidAIMode reports whether s names a mode a client may SET. Unset is deliberately not settable:
// clearing a preference is expressed by choosing one, and accepting "" from a client would make a
// typo indistinguishable from a deliberate reset.
func ValidAIMode(s string) bool {
	switch AIMode(strings.ToLower(strings.TrimSpace(s))) {
	case AIModeDeterministic, AIModeEngineer, AIModeFull:
		return true
	}
	return false
}

// AIPermissions is the resolved answer for a tenant: what may actually run right now, after the
// plan, the customer's choice and the kill-switch have all had their say.
type AIPermissions struct {
	// Engineer permits the AI Security Engineer (triage, fixes, narrative).
	Engineer bool `json:"engineer"`
	// Pentester permits the AI Pentester (exploitation, proof).
	Pentester bool `json:"pentester"`
	// Mode is the effective mode after resolution.
	Mode AIMode `json:"mode"`
	// Reason states WHY, in the customer's terms, so a disabled surface can explain itself instead of
	// looking broken. Always populated.
	Reason string `json:"reason"`
}

// ResolveAI computes what may run for a tenant.
//
// Order matters and encodes the precedence: the kill-switch beats everything, the customer's explicit
// choice beats the plan's generosity, and the plan caps what an unset preference gets. A tenant can
// always choose LESS than their plan allows; they can never choose more.
func (t Tenant) ResolveAI() AIPermissions {
	if t.AgentsHalted {
		return AIPermissions{Mode: AIModeDeterministic,
			Reason: "All autonomous agent activity is frozen by your kill-switch. Deterministic scanning continues."}
	}

	lim := Entitlements(t.Plan)
	entitledEngineer := lim.AIEnabled || t.LLM.Usable()
	entitledPentester := (lim.AIEnabled || t.LLM.Usable()) && (lim.AutonomousPentest || t.LLM.Usable())

	switch t.AIMode {
	case AIModeDeterministic:
		return AIPermissions{Mode: AIModeDeterministic,
			Reason: "You chose deterministic-only. Scanners, correlation and plain-English findings run; no AI agent does, and no tokens are spent."}
	case AIModeEngineer:
		if !entitledEngineer {
			return AIPermissions{Mode: AIModeDeterministic,
				Reason: "The AI Security Engineer needs an AI-enabled plan or your own LLM key. Add a key in Settings and it turns on immediately."}
		}
		return AIPermissions{Engineer: true, Mode: AIModeEngineer,
			Reason: "The AI Security Engineer is on. The AI Pentester is off by your choice."}
	case AIModeFull:
		if !entitledEngineer {
			return AIPermissions{Mode: AIModeDeterministic,
				Reason: "The AI agents need an AI-enabled plan or your own LLM key. Add a key in Settings and they turn on immediately."}
		}
		return AIPermissions{Engineer: true, Pentester: entitledPentester, Mode: AIModeFull,
			Reason: fullReason(entitledPentester)}
	}

	// Unset — fall back to the plan, which is exactly today's behaviour.
	switch {
	case entitledEngineer && entitledPentester:
		return AIPermissions{Engineer: true, Pentester: true, Mode: AIModeFull,
			Reason: "Both AI agents are available on your plan."}
	case entitledEngineer:
		return AIPermissions{Engineer: true, Mode: AIModeEngineer,
			Reason: "The AI Security Engineer is available on your plan. The AI Pentester needs the pentest add-on."}
	default:
		return AIPermissions{Mode: AIModeDeterministic,
			Reason: "You are on the deterministic engine. Add your own LLM key in Settings, or upgrade, to turn the AI agents on."}
	}
}

func fullReason(pentester bool) string {
	if pentester {
		return "Both AI agents are on."
	}
	return "The AI Security Engineer is on. The AI Pentester needs the pentest add-on on your plan."
}
