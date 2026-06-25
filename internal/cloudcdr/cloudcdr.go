// Package cloudcdr is cloud detection-and-response over the control plane — the ACSP (Agentic Cloud
// Security Platform) "observe live execution" capability applied to the cloud audit log. A connector
// (or the customer) streams normalized control-plane events (AWS CloudTrail / GCP Audit Logs / Azure
// Activity Log); a deterministic rule set flags the risky LIVE actions a periodic posture scan would
// miss for hours — a bucket just made public, a security group opened to the world, a root login, an
// admin policy attached, audit logging disabled. Emits findings into the SAME store the rest of the
// platform reads, so they flow through issues / incidents / grc / hitl like any finding.
//
// LLM-free + grounded (§10): every flag derives from the real event name + request detail. Detection
// only — it never blocks (§13); the cloud provider's own controls do enforcement. Sibling of
// internal/identitythreat (ITDR) and the runtime-events ingest.
package cloudcdr

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Event is a normalized cloud control-plane audit event (the connector maps CloudTrail/GCP/Azure
// records onto this shape).
type Event struct {
	Provider  string `json:"provider"`   // aws | gcp | azure
	EventName string `json:"event_name"` // the API action, e.g. PutBucketAcl, ConsoleLogin
	Actor     string `json:"actor"`      // who did it (ARN / email / "root")
	Resource  string `json:"resource"`   // the affected resource id/arn
	SourceIP  string `json:"source_ip"`
	Region    string `json:"region"`
	Detail    string `json:"detail"` // request-parameters summary / free text
}

// Threat is a detected risky cloud action.
type Threat struct {
	Rule     string         `json:"rule"`
	Severity types.Severity `json:"severity"`
	Title    string         `json:"title"`
	Event    Event          `json:"event"`
}

type ruleInfo struct {
	mitre string
	cwe   string
}

var ruleMeta = map[string]ruleInfo{
	"public_resource_exposure": {mitre: "T1530", cwe: "CWE-284"},
	"security_group_opened":    {mitre: "T1190", cwe: "CWE-284"},
	"root_console_login":       {mitre: "T1078.004"},
	"iam_privilege_escalation": {mitre: "T1098"},
	"audit_logging_disabled":   {mitre: "T1562.008"},
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// Detect runs the rule set over the events and returns the risky actions, worst-first by input order.
func Detect(events []Event) []Threat {
	var out []Threat
	for _, e := range events {
		if t, ok := classify(e); ok {
			out = append(out, t)
		}
	}
	return out
}

// classify applies the deterministic rules. Matches on the event name + a grounded marker in the
// request detail/resource — so a flag always corresponds to a real risky parameter, never the action
// alone (e.g. PutBucketAcl is only flagged when the ACL actually grants public/AllUsers access).
func classify(e Event) (Threat, bool) {
	name := strings.ToLower(e.EventName)
	detail := strings.ToLower(e.Detail + " " + e.Resource)
	actor := strings.ToLower(e.Actor)
	mk := func(rule string, sev types.Severity, title string) (Threat, bool) {
		return Threat{Rule: rule, Severity: sev, Title: title, Event: e}, true
	}
	res := nz(e.Resource, "a resource")

	switch {
	case containsAny(name, "stoplogging", "deletetrail", "deleteflowlogs", "deletelogginbucket") ||
		(containsAny(name, "updatetrail", "puteventselectors") && strings.Contains(detail, "false")):
		return mk("audit_logging_disabled", types.SeverityHigh, "Cloud audit logging was disabled ("+e.EventName+")")

	case strings.Contains(name, "consolelogin") && (actor == "root" || strings.Contains(actor, ":root") || strings.Contains(detail, "root")):
		return mk("root_console_login", types.SeverityHigh, "Root account console login from "+nz(e.SourceIP, "an unknown IP"))

	case containsAny(name, "putbucketacl", "putbucketpublicaccessblock", "putobjectacl", "putbucketpolicy", "setiampolicy", "storage.setiampermissions") &&
		containsAny(detail, "allusers", "public", "0.0.0.0/0", "allauthenticatedusers", "\"*\"", "allow_all"):
		return mk("public_resource_exposure", types.SeverityHigh, "A storage resource was exposed publicly ("+res+")")

	case containsAny(name, "authorizesecuritygroupingress", "createfirewallrule", "patchfirewall", "modifynetworkacl", "createnetworksecuritygroup") &&
		containsAny(detail, "0.0.0.0/0", "::/0", "any", "internet"):
		return mk("security_group_opened", types.SeverityHigh, "A security group/firewall was opened to the internet ("+res+")")

	case containsAny(name, "attachuserpolicy", "attachrolepolicy", "putuserpolicy", "putrolepolicy", "roleassignments/write") &&
		containsAny(detail, "administrator", "admin", "owner", "\"*\"", "*:*"):
		return mk("iam_privilege_escalation", types.SeverityHigh, "An admin/owner policy was attached to an identity ("+res+")")

	case containsAny(name, "createaccesskey", "createloginprofile", "updateloginprofile", "createserviceaccountkey"):
		return mk("iam_privilege_escalation", types.SeverityMedium, "New long-lived credentials were created for an identity ("+res+")")
	}
	return Threat{}, false
}

// Findings maps detected threats into engine findings (cloudcdr:: rule ids) so they flow through the
// same store / issues / incidents machinery as any finding. Mirrors identitythreat.Findings.
func Findings(threats []Threat) []types.Finding {
	out := make([]types.Finding, 0, len(threats))
	for _, t := range threats {
		m := ruleMeta[t.Rule]
		f := types.Finding{
			RuleID: "cloudcdr::" + t.Rule, Tool: "cloudcdr",
			Severity: t.Severity, Endpoint: "cloud:" + nz(t.Event.Resource, t.Event.EventName), Title: t.Title,
			Description: describe(t),
		}
		if m.cwe != "" {
			f.CWE = []string{m.cwe}
		}
		if m.mitre != "" {
			f.MITRETechniques = []string{m.mitre}
		}
		out = append(out, f)
	}
	return out
}

func describe(t Threat) string {
	parts := []string{t.Event.Provider + " control-plane action: " + t.Event.EventName}
	if t.Event.Actor != "" {
		parts = append(parts, "actor "+t.Event.Actor)
	}
	if t.Event.SourceIP != "" {
		parts = append(parts, "from "+t.Event.SourceIP)
	}
	if t.Event.Region != "" {
		parts = append(parts, "region "+t.Event.Region)
	}
	return strings.Join(parts, "; ")
}
