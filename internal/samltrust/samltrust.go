// Package samltrust assesses AWS roles assumable via SAML federation — the path an Okta, Entra or
// ADFS identity takes into a cloud account.
//
// It is the sibling of internal/ghoidc (GitHub Actions → AWS, OIDC web identity) and internal/gcpwif
// (GitHub → GCP, workload identity). Those two cover CI; this covers the WORKFORCE IdP, which is how
// most people actually reach an AWS account and which both of them deliberately refuse to judge.
//
// # What it will and will not decide
//
// ONE thing is decidable from a trust policy alone, and it is the one that matters: whether the
// policy requires a SAML:aud condition. AWS puts the audience of the assertion in that key, so a
// trust that does not constrain it accepts an assertion minted for ANY service provider the IdP
// serves — not just AWS. An attacker who can obtain an assertion for some other application at the
// same IdP can present it here.
//
// ADEQUACY OF A PRESENT CONDITION IS NOT DECIDED. That is gcpwif's rule and it holds for the same
// reason: judging whether someone's condition is "good enough" means evaluating their intent, and a
// package that guesses at that produces confident findings it cannot support. An ABSENT condition is
// a fact; a present one is only the lexical fact that they thought about it.
//
// Nor is blast radius inferred: a trust policy says who may assume the role, never what the role can
// do. Privileged is SUPPLIED by the caller from real IAM data or not used at all — the same rule
// ghoidc follows.
package samltrust

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Role is one AWS role and the trust policy that decides who may assume it.
type Role struct {
	ARN         string
	Name        string
	TrustPolicy string
	// Privileged reports that the role holds administrative permissions. Supplied by the caller
	// from IAM data, never inferred here.
	Privileged bool
}

// Estate is the observed SAML-federation surface.
type Estate struct{ Roles []Role }

// Assessment is what was found, and what could not be looked at.
type Assessment struct {
	Findings []types.Finding
	// ChecksNotRun explains, per role, why it was skipped — so a caller never reads "0 findings" as
	// a clean estate when a policy could not be parsed.
	ChecksNotRun map[string]string
}

// RuleUnconstrainedAudience fires when a SAML trust does not require SAML:aud.
const RuleUnconstrainedAudience = "saml_trust_audience_unconstrained"

// samlAudKey is the condition key AWS populates with the assertion's Audience. Compared
// case-insensitively: IAM condition keys are not case-sensitive and policies in the wild write it
// as SAML:aud, saml:aud and SAML:Aud.
const samlAudKey = "saml:aud"

// Assess evaluates every role's trust policy for unconstrained SAML federation.
//
// Grounded (§10): a finding comes only from a statement that really ALLOWS a SAML assume-role to a
// real federated principal and really carries no audience condition. A Deny is the policy working
// and is never reported; an unparseable policy is declared, never treated as clean.
func Assess(est Estate, now time.Time) Assessment {
	a := Assessment{ChecksNotRun: map[string]string{}}
	n := 0
	id := func() string { n++; return fmt.Sprintf("samltrust-%03d", n) }

	for _, role := range est.Roles {
		if strings.TrimSpace(role.TrustPolicy) == "" {
			continue // no trust policy observed: nothing to assess, and nothing claimed
		}
		doc, err := cloudiam.Parse([]byte(role.TrustPolicy))
		if err != nil || doc == nil {
			a.ChecksNotRun["saml_trust:"+role.ARN] = "the trust policy could not be parsed — this " +
				"role was NOT assessed for SAML federation and must not be read as clean"
			continue
		}
		for _, st := range doc.Statement {
			provs, ok := samlAllowStatement(st)
			if !ok {
				continue
			}
			if hasAudienceCondition(st) {
				// A present condition is not judged. Whether it names the right audience is the
				// customer's intent, and asserting on it would be a guess wearing a finding's
				// clothes.
				continue
			}
			a.Findings = append(a.Findings, audienceFinding(id(), role, provs, now))
		}
	}
	return a
}

// samlAllowStatement reports the federated principals an Allow of sts:AssumeRoleWithSAML grants to.
func samlAllowStatement(st cloudiam.Statement) ([]string, bool) {
	if !strings.EqualFold(st.Effect, "Allow") {
		return nil, false // a Deny naming a provider is the policy refusing it
	}
	if !hasSAMLAssumeAction(st.Action) {
		return nil, false
	}
	provs := federatedPrincipals(st.Principal)
	if len(provs) == 0 {
		return nil, false
	}
	return provs, true
}

func hasSAMLAssumeAction(actions []string) bool {
	for _, a := range actions {
		switch strings.ToLower(strings.TrimSpace(a)) {
		case "*", "sts:*", "sts:assumerolewithsaml":
			return true
		}
	}
	return false
}

// hasAudienceCondition reports whether ANY condition operator constrains SAML:aud.
//
// Operator-agnostic on purpose. StringEquals, StringLike and ForAllValues:StringEquals all constrain
// the audience; which one is right is the customer's judgement, and this package only decides
// whether they made one at all.
func hasAudienceCondition(st cloudiam.Statement) bool {
	for _, keys := range st.Condition {
		m, ok := keys.(map[string]interface{})
		if !ok {
			continue
		}
		for k := range m {
			if strings.EqualFold(strings.TrimSpace(k), samlAudKey) {
				return true
			}
		}
	}
	return false
}

// federatedPrincipals returns the Federated principals of a statement — the SAML provider ARNs.
//
// Only the Federated key counts. An AWS principal is a different trust entirely and belongs to the
// evaluator, not here.
func federatedPrincipals(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]interface{}
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	fed, ok := obj["Federated"]
	if !ok {
		return nil
	}
	var out []string
	switch t := fed.(type) {
	case string:
		if v := strings.TrimSpace(t); v != "" {
			out = append(out, v)
		}
	case []interface{}:
		for _, e := range t {
			if v, ok := e.(string); ok && strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
	}
	return out
}

func audienceFinding(fid string, role Role, provs []string, now time.Time) types.Finding {
	sev := types.SeverityHigh
	desc := "Role " + role.ARN + " can be assumed with a SAML assertion from " +
		strings.Join(provs, ", ") + ", and the trust policy requires no SAML:aud condition. AWS puts " +
		"the assertion's audience in that key, so this accepts an assertion minted for ANY service " +
		"provider the identity provider serves — not only AWS. Anyone able to obtain an assertion for " +
		"another application at the same IdP can present it here."
	if role.Privileged {
		sev = types.SeverityCritical
		desc += " This role holds administrative permissions, so the path is an account takeover."
	}
	return types.Finding{
		ID:       fid,
		RuleID:   "samltrust::" + RuleUnconstrainedAudience,
		Tool:     "samltrust",
		Severity: sev,
		// CWE-1390 weak authentication / CWE-284 improper access control: the condition IS the
		// access-control decision for a federated assume-role.
		CWE:                []string{"CWE-1390", "CWE-284"},
		Endpoint:           role.ARN,
		Title:              "SAML trust on " + roleLabel(role) + " does not constrain the assertion audience",
		Description:        desc,
		MITRETechniques:    []string{"T1199"}, // trusted relationship
		VerificationStatus: types.VerificationPatternMatch,
		DiscoveredAt:       now,
		ToolArgs: map[string]string{
			"role": role.ARN, "providers": strings.Join(provs, ","),
			"privileged": fmt.Sprintf("%t", role.Privileged),
			"fix": "add a Condition requiring SAML:aud, e.g. StringEquals " +
				`{"SAML:aud":"https://signin.aws.amazon.com/saml"}`,
		},
	}
}

func roleLabel(r Role) string {
	if strings.TrimSpace(r.Name) != "" {
		return r.Name
	}
	return r.ARN
}
