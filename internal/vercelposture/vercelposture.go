// Package vercelposture is DEPLOYMENT-PLATFORM POSTURE for the stack this segment actually runs on.
//
// WHY VERCEL. Our twelve integrations are an enterprise set — Okta, M365, Azure, GitLab. A seed or
// Series-A company ships on Vercel, and the exposures that come with it are not covered by anything
// else we have: they are not cloud-IAM misconfigurations, they are not code findings, and no scanner
// will find them because the surface is the platform's own configuration.
//
// The one that matters most is PREVIEW DEPLOYMENTS. Every pull request gets a public URL. That URL
// commonly runs production-like code against production-like data, and by default it is reachable by
// anyone who learns the address — which is guessable, is in the PR, and is in certificate-transparency
// logs. A company can have a locked-down production domain and still be handing out an unauthenticated
// copy of it on every branch. That is a real breach path and it is close to invisible without looking
// at the platform config directly.
//
// # Grounded (§10), with the refusals
//
//   - EVERY FINDING NAMES THE PROJECT AND THE SETTING. No "your deployments may be exposed" — the
//     project, the environment, and the toggle that produced the verdict.
//   - PROTECTED IS PROTECTED. A project with deployment protection on yields nothing, however alarming
//     its name. A clean estate is silent.
//   - ABSENT CONFIG IS NOT INSECURE CONFIG. A snapshot that does not say whether protection is enabled
//     produces no finding, because "we were not told" and "it is off" are different facts and only one
//     of them is a vulnerability.
//
// Snapshot-driven, LLM-free, deterministic — the same shape as sspm / osint / tprm / deviceposture, so
// the posted-snapshot path works today and a live fetcher (the Vercel API, with a token the customer
// pastes) is the credential-gated half.
package vercelposture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// EnvVar is one environment variable's METADATA. The value is never carried: knowing that
// DATABASE_URL exists in the preview environment is the finding; reading it would be the breach.
type EnvVar struct {
	Key string `json:"key"`
	// Targets are the environments it is exposed to: production | preview | development.
	Targets []string `json:"targets,omitempty"`
	// Sensitive marks a Vercel "sensitive" variable (write-only, not readable back in the dashboard).
	Sensitive bool `json:"sensitive,omitempty"`
}

// Project is one Vercel project's security-relevant configuration.
type Project struct {
	Name string `json:"name"`
	// ProductionProtected / PreviewProtected report deployment protection (password, SSO or
	// trusted-IP). Pointers because ABSENT and FALSE are different facts: a snapshot that does not
	// carry the setting must not be read as "unprotected".
	ProductionProtected *bool `json:"production_protected,omitempty"`
	PreviewProtected    *bool `json:"preview_protected,omitempty"`
	// PublicSource reports Vercel's "source protection" being off — the /_src route exposing the
	// project's source and env to anyone.
	PublicSource *bool    `json:"public_source,omitempty"`
	EnvVars      []EnvVar `json:"env_vars,omitempty"`
	// ProductionDomains are the live hostnames, so a finding can name what is actually exposed.
	ProductionDomains []string `json:"production_domains,omitempty"`
}

// Snapshot is the posted account state.
type Snapshot struct {
	Projects []Project `json:"projects"`
}

// Options tunes the assessment (injectable clock + ids, as the sibling assessors do).
type Options struct {
	Now   func() time.Time
	NewID func() string
}

// Assess turns the snapshot into grounded deployment-posture findings. A well-configured account —
// preview protected, source private, no production secrets leaking into preview — yields nil.
func Assess(s Snapshot, opts Options) []types.Finding {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	n := 0
	id := func() string {
		n++
		if opts.NewID != nil {
			return opts.NewID()
		}
		return fmt.Sprintf("vp-%d", n)
	}

	var out []types.Finding
	for _, p := range s.Projects {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue // an unnamed project cannot be acted on
		}

		// THE HEADLINE EXPOSURE: an unprotected preview deployment. Every PR publishes one, the URL is
		// in the PR and in CT logs, and it usually runs production-like code.
		if isFalse(p.PreviewProtected) {
			out = append(out, finding(id(), "vercel::preview-unprotected", types.SeverityHigh,
				"Preview deployments are public: "+name, name,
				fmt.Sprintf("Every pull request on %s publishes a preview URL that anyone can open — no password, "+
					"no SSO. Those URLs appear in pull requests and in certificate-transparency logs, so they are "+
					"found without guessing. Preview builds usually run the same code as production, often against "+
					"production-like data. Turn on Deployment Protection for Preview in the project's settings.", name),
				now, comp(types.Compliance{
					SOC2: []string{"CC6.1", "CC6.6"}, GDPR: []string{"Art. 32"},
					NIST80053: []string{"AC-3", "SC-7"}, CISv8: []string{"3.3", "4.1"},
					ISO27001: []string{"A.8.16", "A.8.31"},
				})))
		}

		// Production-only secrets that are ALSO exposed to preview. The preview environment is the
		// weaker one; a production credential reachable from it inherits that weakness.
		if leaked := prodSecretsInPreview(p); len(leaked) > 0 {
			out = append(out, finding(id(), "vercel::production-secret-in-preview", types.SeverityHigh,
				"Production secrets are available to preview builds: "+name, name,
				fmt.Sprintf("On %s these variables are exposed to the preview environment as well as production: %s. "+
					"Preview builds run on every branch, including from forks and unreviewed code, so a production "+
					"credential reachable there is only as protected as the least-reviewed pull request. Scope them "+
					"to Production only, and give preview its own credentials.", name, strings.Join(leaked, ", ")),
				now, comp(types.Compliance{
					SOC2: []string{"CC6.1", "CC6.3"}, PCI: []string{"7.2.1"},
					NIST80053: []string{"AC-6", "SC-28"}, ISO27001: []string{"A.8.3"},
				})))
		}

		// Source protection off — /_src exposes the project's source and configuration.
		if isFalse(p.PublicSource) {
			out = append(out, finding(id(), "vercel::source-publicly-readable", types.SeverityHigh,
				"Deployment source is publicly readable: "+name, name,
				fmt.Sprintf("%s serves its source and build configuration publicly. Anyone can read the code, and "+
					"anything checked into it. Enable Source Protection in the project's settings.", name),
				now, comp(types.Compliance{
					SOC2: []string{"CC6.1"}, GDPR: []string{"Art. 32"},
					NIST80053: []string{"AC-3"}, ISO27001: []string{"A.8.4"},
				})))
		}

		// Unprotected production is lower severity than it sounds: a production site is USUALLY meant
		// to be public. It is reported only as context alongside a real exposure, never on its own —
		// flagging "your website is reachable" would be exactly the noise that trains people to ignore
		// us.
		if isFalse(p.ProductionProtected) && isFalse(p.PublicSource) {
			out = append(out, finding(id(), "vercel::production-unprotected-with-public-source",
				types.SeverityMedium,
				"Production is open and its source is readable: "+name, name,
				fmt.Sprintf("%s has no deployment protection on production AND serves its source publicly. Either "+
					"alone can be intentional; together they mean anyone can read the code behind a site they can "+
					"also reach.%s", name, domainNote(p.ProductionDomains)),
				now, comp(types.Compliance{
					SOC2: []string{"CC6.1"}, NIST80053: []string{"AC-3"}, ISO27001: []string{"A.8.4"},
				})))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}

// prodSecretsInPreview returns variables that look like credentials AND are exposed to preview as well
// as production.
//
// It reports the KEY only, never a value — the snapshot does not carry values by design.
func prodSecretsInPreview(p Project) []string {
	var out []string
	for _, v := range p.EnvVars {
		if !hasTarget(v.Targets, "production") || !hasTarget(v.Targets, "preview") {
			continue
		}
		if !looksLikeCredential(v.Key) {
			continue // a feature flag shared across environments is not a finding
		}
		out = append(out, v.Key)
	}
	sort.Strings(out)
	return out
}

// looksLikeCredential recognises the naming conventions people actually use. Deliberately conservative:
// a false NEGATIVE costs one missed finding, a false POSITIVE puts noise in front of someone who will
// then trust the next one less.
func looksLikeCredential(key string) bool {
	k := strings.ToLower(key)
	for _, tok := range []string{
		"secret", "token", "password", "passwd", "api_key", "apikey", "private_key",
		"credential", "database_url", "db_url", "dsn", "access_key", "client_secret",
		"webhook_url", "signing", "_pat", "auth",
	} {
		if strings.Contains(k, tok) {
			return true
		}
	}
	return false
}

func hasTarget(targets []string, want string) bool {
	for _, t := range targets {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}

// isFalse reports an EXPLICIT false. A nil pointer means the snapshot did not carry the setting, and
// absent config is not insecure config — we were not told, which is a different fact from "it is off".
func isFalse(b *bool) bool { return b != nil && !*b }

func domainNote(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return " Live at: " + strings.Join(domains, ", ") + "."
}

func finding(fid, rule string, sev types.Severity, title, project, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "vercelposture", Severity: sev,
		Title: title, Endpoint: "vercel:" + project, Description: desc,
		DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: c,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }
