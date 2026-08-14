// Package dataplatform is DATA-WAREHOUSE ACCESS POSTURE — who can read which table.
//
// THE GAP IT CLOSES. cloudgraph already classifies BigQuery, Redshift, Spanner and the rest as data
// stores (classify.go), so an attack path can reach a warehouse and say "this leads to data". What it
// cannot say is who holds the keys to what INSIDE it: cloud IAM governs access to the RESOURCE, while a
// warehouse runs its own grant system underneath — a Snowflake role with SELECT on analytics.customers
// is invisible to every AWS/GCP/Azure policy evaluator we have. Snowflake is not a cloud-provider
// resource at all, so it never appears in an inventory in the first place.
//
// That matters because the warehouse is usually where the regulated data actually sits. An attack path
// that ends at "reaches the data store" has stopped one step short of the fact a responder needs: the
// table, and the grant that exposes it.
//
// GROUNDED (§10), with four refusals that carry most of the value:
//
//   - SENSITIVITY IS DECLARED OR DISCOVERED, never GUESSED FROM A NAME. We do not guess from a table
//     called "customers" — a name is not a classification, and a wrong one either cries wolf or grants
//     false comfort. It may be DECLARED by the owner, or DISCOVERED by Classify from a sampled column's
//     actual values (value-proven only — see Classify). An estate that supplies neither still gets every
//     public-grant finding (those do not need it); it just does not get the sensitivity-specific ones.
//   - EXTERNAL REQUIRES KNOWING WHO IS INTERNAL. Without OrgDomains we cannot tell a contractor from an
//     employee, so the external-grant check does not run at all rather than guess a domain.
//   - STALENESS REQUIRES A LAST-USED TIMESTAMP. Absent, no finding — an unrecorded grant is unknown, not
//     unused.
//   - PUBLIC IS NOT ONE THING. allUsers is the internet; allAuthenticatedUsers is any account at the
//     provider, still outside the org; PUBLIC in Snowflake or Postgres is everyone INSIDE the account.
//     They differ by orders of magnitude in blast radius, so they are separate findings at separate
//     severities rather than one flattened "public access" alarm.
//
// Snapshot-driven, LLM-free, deterministic; a well-governed estate yields ZERO findings. Mirrors the
// sspm / osint / tprm / deviceposture assessors, so the posted-snapshot path works today and the live
// connector (Snowflake ACCOUNT_USAGE, BigQuery getIamPolicy, Postgres information_schema) is the honest
// credential-gated half.
package dataplatform

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/dataclass"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Grant is one privilege held by one grantee on one object. Every field is a stated fact from the
// warehouse's own catalog — nothing here is inferred.
type Grant struct {
	// Grantee is the role, user, service account or group holding the privilege — verbatim, so a
	// reader can find it in the warehouse (e.g. "PUBLIC", "allUsers", "analyst@acme.com").
	Grantee string `json:"grantee"`
	// GranteeType is role | user | service_account | group | public | external, when the catalog says.
	// Optional: the public checks recognise the well-known grantee NAMES on their own, so an export
	// that omits the type still gets them.
	GranteeType string `json:"grantee_type,omitempty"`
	// Privilege is the granted right, verbatim (SELECT, ALL, OWNERSHIP, INSERT, ...).
	Privilege string `json:"privilege"`
	// LastUsed is when this grant was last exercised (RFC3339 or 2006-01-02), when the platform records
	// it. Empty means UNKNOWN, which is not the same as unused — the stale check skips it.
	LastUsed string `json:"last_used,omitempty"`
}

// Object is one thing in the warehouse that grants attach to.
type Object struct {
	// Platform is snowflake | bigquery | postgres | redshift | databricks.
	Platform string `json:"platform"`
	// Name is the fully-qualified name (analytics.public.customers, project.dataset).
	Name string `json:"name"`
	// Type is table | view | schema | database | dataset.
	Type string `json:"type,omitempty"`
	// Sensitive says this object holds regulated or personal data. DECLARED by the owner or set by an
	// upstream classifier — never inferred from the name here.
	Sensitive bool `json:"sensitive,omitempty"`
	// DataClasses optionally names what kind (pii, phi, pci, secrets), for the finding text.
	DataClasses []string `json:"data_classes,omitempty"`
	// Columns is an OPTIONAL sample of the object's fields — names and a bounded sample of values —
	// used to DISCOVER sensitivity rather than wait for it to be declared. Empty → the object's
	// sensitivity is whatever was declared (today's behaviour). See Classify.
	Columns []dataclass.Column `json:"columns,omitempty"`
	// Grants is who can do what to it.
	Grants []Grant `json:"grants,omitempty"`
}

// Estate is the posted snapshot.
type Estate struct {
	Objects []Object `json:"objects"`
	// OrgDomains are the email domains that count as INTERNAL (acme.com, acme.io). Without them the
	// external-grant check does not run — we will not guess who works here.
	OrgDomains []string `json:"org_domains,omitempty"`
	// StaleDays is how long unused before a grant is stale. 0 → the default below.
	StaleDays int `json:"stale_days,omitempty"`
}

// DefaultStaleDays is the unused-grant window. 90 days is a quarter — long enough that a genuinely
// seasonal job is not flagged, short enough that a departed contractor's access is.
const DefaultStaleDays = 90

// Options tunes the assessment (injectable clock + ids, as the sibling assessors do).
type Options struct {
	Now   func() time.Time
	NewID func() string
}

// Discovery records that an object's sensitivity was DISCOVERED from its data rather than declared — the
// evidence a crown jewel now rests on instead of a checkbox.
type Discovery struct {
	Object   string   `json:"object"`
	Classes  []string `json:"classes"`  // the discovered data classes (pii, pci, …)
	Evidence []string `json:"evidence"` // the per-column, value-proven reasons
}

// Classify DISCOVERS sensitivity from any object carrying sampled Columns, and returns the estate with
// discovered objects marked sensitive plus a record of what was found. This is what turns dataplatform's
// declared flag into an evidence-based one, so the graph's crown jewel is a fact.
//
// The discipline is deliberately asymmetric and grounded (§10):
//
//   - UPGRADE ONLY, NEVER DOWNGRADE. An object the customer declared sensitive stays sensitive whatever
//     a sample shows — a sample is a few rows, and its silence is not proof the column is clean. We can
//     add a crown jewel the owner missed; we must never remove one they asserted.
//   - VALUE-PROVEN ONLY. Only a Confirmed classification (actual values matched a structure-checked
//     pattern) flips an undeclared object to sensitive. A Suspected, name-only signal is a prompt to
//     sample, not a verdict — and treating a column NAME as proof is the exact inference dataplatform
//     refuses at the object level. So the bar to CREATE a crown jewel is the data itself testifying.
//   - CARRIES ITS EVIDENCE. Each discovery names the classes and the per-column reasons, so an
//     upgraded object is auditable — never "trust me, it's sensitive now".
//
// An estate with no sampled columns comes back unchanged (nil discoveries), so this is purely additive.
func Classify(est Estate) (Estate, []Discovery) {
	var discoveries []Discovery
	for i := range est.Objects {
		o := &est.Objects[i]
		if len(o.Columns) == 0 {
			continue
		}
		res := dataclass.Classify(dataclass.Object{Name: o.Name, Columns: o.Columns})
		// Only value-proven evidence may CREATE a crown jewel. A name-only suspicion does not.
		if res.HighestConfidence != dataclass.Confirmed {
			continue
		}
		classes := make([]string, 0, len(res.Classes))
		for _, c := range res.Classes {
			classes = append(classes, string(c))
		}
		var evidence []string
		for _, m := range res.Matches {
			if m.Confidence == dataclass.Confirmed {
				evidence = append(evidence, m.Column+": "+m.Evidence)
			}
		}
		discoveries = append(discoveries, Discovery{Object: o.Name, Classes: classes, Evidence: evidence})

		// Upgrade: mark sensitive and union the discovered classes into whatever was declared. Never
		// clears a declaration; a declared-sensitive object simply gains the discovered class labels.
		o.Sensitive = true
		o.DataClasses = unionClasses(o.DataClasses, classes)
	}
	return est, discoveries
}

func unionClasses(declared, discovered []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range append(append([]string{}, declared...), discovered...) {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Assess turns the estate into grounded access-posture findings. A well-governed warehouse — no public
// grants, no external grantees on sensitive data, no stale access — yields nil.
func Assess(est Estate, opts Options) []types.Finding {
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
		return fmt.Sprintf("dp-%d", n)
	}
	staleDays := est.StaleDays
	if staleDays <= 0 {
		staleDays = DefaultStaleDays
	}
	// Absent org domains, "external" is unknowable — the check is skipped entirely rather than guessed.
	domains := normalizeDomains(est.OrgDomains)

	var out []types.Finding
	for _, o := range est.Objects {
		obj := strings.TrimSpace(o.Name)
		if obj == "" {
			continue // an unnamed object cannot be acted on, and naming it "unknown" helps nobody
		}
		where := objectLabel(o)

		for _, g := range o.Grants {
			grantee := strings.TrimSpace(g.Grantee)
			canRead, canWrite := readsData(g.Privilege), writesData(g.Privilege)
			if grantee == "" || (!canRead && !canWrite) {
				continue // USAGE on a schema and friends touch no rows — not a data-exposure finding
			}
			// The verb has to follow the privilege. A public INSERT is a real problem (anyone can
			// poison the table) but calling it "readable" would be a plain false statement, and a
			// finding that misdescribes its own evidence is the thing every check here exists to avoid.
			verb := "readable"
			switch {
			case canRead && canWrite:
				verb = "readable and writable"
			case canWrite:
				verb = "writable"
			}

			switch scopeOf(grantee, g.GranteeType) {
			case scopeInternet:
				out = append(out, finding(id(), "dataplatform::internet-public-grant", types.SeverityCritical,
					"Data is "+verb+" by anyone on the internet: "+where, o,
					fmt.Sprintf("%s grants %s to %q — that is the whole internet, unauthenticated. %s Revoke it and grant to a named role instead.",
						where, priv(g.Privilege), grantee, classSentence(o)),
					now, exposureCompliance(o)))
				continue
			case scopeProviderWide:
				out = append(out, finding(id(), "dataplatform::provider-wide-grant", types.SeverityCritical,
					"Data is "+verb+" by any account at the provider: "+where, o,
					fmt.Sprintf("%s grants %s to %q — that is every authenticated account at the provider, not just your organisation. %s Revoke it and grant to a named role instead.",
						where, priv(g.Privilege), grantee, classSentence(o)),
					now, exposureCompliance(o)))
				continue
			case scopeAccountWide:
				sev, what := types.SeverityMedium, "everyone in the account has it"
				if o.Sensitive {
					// The distinction that matters: account-wide on regulated data is a least-privilege
					// failure with real regulatory weight, not just untidy permissions.
					sev, what = types.SeverityHigh, "every user in the account can reach regulated data"
				}
				out = append(out, finding(id(), "dataplatform::account-wide-grant", sev,
					"Data is "+verb+" account-wide: "+where, o,
					fmt.Sprintf("%s grants %s to %q, the built-in everyone role — %s. %s Grant to the specific roles that need it.",
						where, priv(g.Privilege), grantee, what, classSentence(o)),
					now, exposureCompliance(o)))
				continue
			}

			// External grantee — only decidable when we were told who is internal.
			if o.Sensitive && len(domains) > 0 && isExternal(grantee, g.GranteeType, domains) {
				out = append(out, finding(id(), "dataplatform::external-grant-on-sensitive", types.SeverityHigh,
					"Regulated data is granted to an outside party: "+where, o,
					fmt.Sprintf("%s grants %s to %q, which is outside your organisation's domains. %s This is data leaving your control — confirm it is a contracted processor with a DPA, or revoke it.",
						where, priv(g.Privilege), grantee, classSentence(o)),
					now, comp(types.Compliance{
						SOC2: []string{"CC6.1", "CC9.2"}, GDPR: []string{"Art. 28", "Art. 32"},
						HIPAA: []string{"164.308(b)(1)"}, PCI: []string{"12.8"},
						NIST80053: []string{"AC-3", "AC-20"}, ISO27001: []string{"A.5.19", "A.8.3"},
					})))
			}

			// Broad write / ownership on regulated data.
			if o.Sensitive && canWrite && !isAdminRole(grantee) {
				out = append(out, finding(id(), "dataplatform::write-access-on-sensitive", types.SeverityHigh,
					"Regulated data is writable by a non-admin grantee: "+where, o,
					fmt.Sprintf("%s grants %s to %q. Write or ownership rights on regulated data allow silent modification or deletion, which breaks both integrity and the audit trail. %s Reduce to the minimum privilege the workload needs.",
						where, priv(g.Privilege), grantee, classSentence(o)),
					now, comp(types.Compliance{
						SOC2: []string{"CC6.1", "CC6.3"}, PCI: []string{"7.2.1"}, SOX: []string{"ITGC-AC"},
						HIPAA: []string{"164.312(c)(1)"}, NIST80053: []string{"AC-6"}, ISO27001: []string{"A.8.3"},
						CISv8: []string{"3.3", "6.8"},
					})))
			}

			// Stale access — only when the platform actually recorded a last-use.
			if days, ok := unusedFor(g.LastUsed, now); ok && days >= staleDays {
				sev := types.SeverityLow
				if o.Sensitive {
					sev = types.SeverityMedium
				}
				out = append(out, finding(id(), "dataplatform::stale-grant", sev,
					"Unused data access is still granted: "+where, o,
					fmt.Sprintf("%s grants %s to %q, last used %d days ago. Standing access nobody exercises is pure attack surface — it is what a compromised or departed account uses. Revoke it.",
						where, priv(g.Privilege), grantee, days),
					now, comp(types.Compliance{
						SOC2: []string{"CC6.1", "CC6.2"}, PCI: []string{"7.2.4"},
						NIST80053: []string{"AC-2", "AC-6"}, ISO27001: []string{"A.5.18"}, CISv8: []string{"5.3", "6.8"},
					})))
			}
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

// grantScope is how far a grantee reaches. Kept distinct because the blast radii differ by orders of
// magnitude and a single "public" verdict would flatten them.
type grantScope int

const (
	scopeNamed        grantScope = iota // a specific role/user/service account
	scopeAccountWide                    // everyone inside this warehouse account
	scopeProviderWide                   // any authenticated account at the provider — outside the org
	scopeInternet                       // unauthenticated, the whole internet
)

// scopeOf recognises the well-known everyone-grantees by NAME as well as by declared type, so an export
// that omits grantee_type still gets the checks that matter most.
func scopeOf(grantee, granteeType string) grantScope {
	g := strings.ToLower(strings.TrimSpace(grantee))
	switch g {
	case "allusers", "principalset://goog/public:all":
		return scopeInternet
	case "allauthenticatedusers":
		return scopeProviderWide
	case "public", "public_role", "role:public", "group:public":
		return scopeAccountWide
	}
	if strings.EqualFold(strings.TrimSpace(granteeType), "public") {
		// Declared public without a recognised name: account-wide is the conservative reading — we do
		// not upgrade to "internet" on an ambiguous label, because that would be inventing blast radius.
		return scopeAccountWide
	}
	return scopeNamed
}

// isExternal reports whether a grantee is outside the organisation. Only ever called with a non-empty
// domain list, and it decides ONLY on an email-shaped grantee: a bare role name carries no domain, so
// it is treated as internal rather than guessed at.
func isExternal(grantee, granteeType string, domains []string) bool {
	if strings.EqualFold(strings.TrimSpace(granteeType), "external") {
		return true
	}
	at := strings.LastIndex(grantee, "@")
	if at < 0 || at == len(grantee)-1 {
		return false // not email-shaped → no domain to judge → not a claim we can make
	}
	d := strings.ToLower(strings.TrimSpace(grantee[at+1:]))
	for _, od := range domains {
		if d == od || strings.HasSuffix(d, "."+od) {
			return false
		}
	}
	return true
}

func normalizeDomains(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@")))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// readsData reports whether a privilege can read rows.
func readsData(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "select", "read", "all", "all privileges", "ownership", "owner",
		"roles/bigquery.dataviewer", "roles/bigquery.dataeditor", "roles/bigquery.dataowner",
		"roles/bigquery.admin", "roles/viewer", "roles/editor", "roles/owner":
		return true
	}
	return false
}

// writesData reports whether a privilege can modify or destroy data.
func writesData(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "insert", "update", "delete", "truncate", "drop", "modify", "write",
		"all", "all privileges", "ownership", "owner",
		"roles/bigquery.dataeditor", "roles/bigquery.dataowner", "roles/bigquery.admin",
		"roles/editor", "roles/owner":
		return true
	}
	return false
}

// isAdminRole recognises the roles that are SUPPOSED to hold write rights, so the write-on-sensitive
// check reports privilege sprawl rather than the DBA doing their job.
func isAdminRole(grantee string) bool {
	g := strings.ToLower(strings.TrimSpace(grantee))
	for _, a := range []string{"accountadmin", "securityadmin", "sysadmin", "dbadmin", "dba", "admin", "owner", "root", "postgres"} {
		if g == a || strings.HasSuffix(g, "_"+a) || strings.HasPrefix(g, a+"_") {
			return true
		}
	}
	return false
}

// unusedFor returns how many whole days ago a grant was last used. ok is false when the timestamp is
// absent or unparseable — unknown is never reported as unused.
func unusedFor(lastUsed string, now time.Time) (int, bool) {
	s := strings.TrimSpace(lastUsed)
	if s == "" {
		return 0, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			d := int(now.Sub(t).Hours() / 24)
			if d < 0 {
				return 0, false // a future timestamp is bad data, not fresh access
			}
			return d, true
		}
	}
	return 0, false
}

// objectLabel names the object the way a reader would find it in the warehouse.
func objectLabel(o Object) string {
	label := o.Name
	if t := strings.TrimSpace(o.Type); t != "" {
		label = t + " " + label
	}
	if p := strings.TrimSpace(o.Platform); p != "" {
		label += " (" + p + ")"
	}
	return label
}

// classSentence states what kind of data is at stake, only when the estate declared it.
func classSentence(o Object) string {
	if !o.Sensitive {
		return ""
	}
	if len(o.DataClasses) == 0 {
		return "This object is declared to hold regulated or personal data."
	}
	return "This object is declared to hold " + strings.Join(o.DataClasses, ", ") + " data."
}

// exposureCompliance is the control nexus for over-broad READ access. Sensitive objects additionally
// cite the privacy regimes, because that is what changes when the rows are personal data.
func exposureCompliance(o Object) *types.Compliance {
	c := types.Compliance{
		SOC2: []string{"CC6.1", "CC6.3"}, PCI: []string{"7.2.1"}, CISv8: []string{"3.3"},
		NISTCSF: []string{"PR.AC-4", "PR.DS-5"}, NIST80053: []string{"AC-3", "AC-6"},
		ISO27001: []string{"A.5.15", "A.8.3"},
	}
	if o.Sensitive {
		c.GDPR = []string{"Art. 5(1)(f)", "Art. 32"}
		c.HIPAA = []string{"164.312(a)(1)"}
		c.CCPA = []string{"§1798.150"}
	}
	return &c
}

func finding(fid, rule string, sev types.Severity, title string, o Object, desc string, now time.Time, c *types.Compliance) types.Finding {
	// The endpoint carries platform + fully-qualified name so the object is unambiguous, and so the
	// platform's target-attribution (data-tier, per-asset compliance) has something literal to match.
	ep := strings.TrimSpace(o.Platform)
	if ep == "" {
		ep = "data"
	}
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "dataplatform", Severity: sev,
		Title: title, Endpoint: ep + ":" + o.Name, Description: desc,
		DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: c,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

// priv renders a privilege for prose without pretending to normalise it — the warehouse's own word is
// what the reader will search for.
func priv(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "access"
	}
	return strings.ToUpper(p)
}
