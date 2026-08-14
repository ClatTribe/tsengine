// Package explain turns a finding into something a founder with no security background can act on.
//
// WHY IT EXISTS. Our audience at this stage has no security engineer. Nobody translates. A finding
// that reads `nuclei::CVE-2021-44228 · critical · CWE-502 · https://app/api/log` is, to the person who
// has to decide what to do on Monday, indistinguishable from noise — so it gets deferred, and the
// engine's recall is wasted at the last inch.
//
// It is also a PRECONDITION FOR THE FIX LOOP, which is easy to miss. A remediation stops at the HITL
// gate for a human to approve. If that human cannot read the finding, they do not approve the fix, and
// the loop never closes. Plain English is not polish on top of the engineer — it is load-bearing for
// it.
//
// # Deterministic first
//
// This runs with the AI turned OFF. Everything here is templates over data the deterministic engine
// already produced (CWE class, L1.5 enrichment, the estate graph). An LLM may later rewrite for
// fluency, but it is never REQUIRED — otherwise "deterministic mode" would mean "unreadable mode",
// and the cheapest tier would be the one nobody can use.
//
// # Urgency is grounded, not a severity label
//
// Every scanner says CRITICAL, so the word has stopped carrying information. We answer the actual
// question — should I drop what I am doing? — from facts, and we SHOW the facts:
//
//	now         someone is exploiting this class in the wild (CISA KEV), or we proved it here
//	this week   likely to be exploited (EPSS) and reachable from the internet
//	this month  serious, but nothing indicates it is being exploited or reachable
//	whenever    real, low impact
//
// Severity alone never reaches "now". A scanner's opinion is not evidence that anyone is attacking you.
//
// # Blast radius comes from the graph or is absent
//
// "Why it matters" is the sentence that makes someone act, and it is the easiest place to bullshit.
// So it is derived from what the estate graph PROVES this reaches, and when the graph has not been
// consulted we say we have not traced it — never a boilerplate "could lead to data loss". An absent
// blast radius is honest; an invented one teaches the reader to discount every future one.
package explain

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Urgency answers "should I drop what I am doing?", grounded in evidence rather than a severity label.
type Urgency string

const (
	UrgencyNow       Urgency = "now"
	UrgencyThisWeek  Urgency = "this_week"
	UrgencyThisMonth Urgency = "this_month"
	UrgencyWhenever  Urgency = "whenever"
)

// Label is the phrase shown to a human.
func (u Urgency) Label() string {
	switch u {
	case UrgencyNow:
		return "Fix today"
	case UrgencyThisWeek:
		return "Fix this week"
	case UrgencyThisMonth:
		return "Fix this month"
	default:
		return "Fix when convenient"
	}
}

// Rank orders urgencies for sorting (higher = sooner).
func (u Urgency) Rank() int {
	switch u {
	case UrgencyNow:
		return 3
	case UrgencyThisWeek:
		return 2
	case UrgencyThisMonth:
		return 1
	}
	return 0
}

// Context is what the rest of the platform knows about this finding's surroundings. All optional: an
// explanation degrades honestly without it rather than inventing the missing half.
type Context struct {
	// Reaches is what the estate graph PROVES this finding's endpoint leads to, in plain terms
	// ("your customer table", "an admin identity"). Only proven paths belong here.
	Reaches []string
	// ReachTraced records whether the graph was actually consulted. This distinguishes "we traced it
	// and it reaches nothing important" from "we never looked" — two very different sentences, and
	// collapsing them is how a reader learns to distrust the whole field.
	ReachTraced bool
	// UnderAttack is a runtime observation that this endpoint is being attacked in production.
	UnderAttack bool
	// AssetLabel is what the customer calls the thing ("your API", "the marketing site").
	AssetLabel string
}

// Technical is the jargon, kept OUT of the readable surface and available on drill-down. It is not
// hidden because it is unimportant — it is what a future security hire or an auditor will want — but
// putting CWE-89 in the headline is what makes the headline unreadable.
type Technical struct {
	RuleID   string   `json:"rule_id,omitempty"`
	Tool     string   `json:"tool,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Endpoint string   `json:"endpoint,omitempty"`
}

// Explanation is the four-line answer: what broke, why it matters here, what to do, how soon.
type Explanation struct {
	Headline     string  `json:"headline"`
	What         string  `json:"what"`
	Why          string  `json:"why"`
	Fix          string  `json:"fix"`
	Urgency      Urgency `json:"urgency"`
	UrgencyLabel string  `json:"urgency_label"`
	// Because lists the FACTS behind the urgency, so the reader can check our reasoning instead of
	// trusting a label. This is the anti-"everything is critical" mechanism.
	Because   []string  `json:"because,omitempty"`
	Technical Technical `json:"technical"`
}

// Explain renders a finding for a non-security reader.
func Explain(f types.Finding, ctx Context) Explanation {
	cls, subject := classify(f)
	urg, because := urgency(f, ctx)

	e := Explanation{
		What:         cls.what,
		Fix:          cls.fix,
		Urgency:      urg,
		UrgencyLabel: urg.Label(),
		Because:      because,
		Technical: Technical{
			RuleID: f.RuleID, Tool: f.Tool, CWE: f.CWE,
			Severity: string(f.Severity), Endpoint: f.Endpoint,
		},
	}
	e.Why = why(ctx)
	e.Headline = headline(cls, subject, ctx)
	return e
}

// why states the blast radius from the graph, or admits we have not traced it.
//
// The two "empty" cases are deliberately different sentences. "We traced this and it does not reach
// anything sensitive" is a finding in itself and lets someone deprioritise with confidence. "We have
// not traced it" is an admission. Rendering both as silence would let a reader assume the first when
// the truth is the second.
func why(ctx Context) string {
	switch {
	case len(ctx.Reaches) > 0:
		return "From here an attacker reaches " + humanList(ctx.Reaches) + "."
	case ctx.ReachTraced:
		return "We traced where this leads and found no path to sensitive data or an admin account. " +
			"That lowers the stakes — it does not make it safe."
	default:
		return "We have not traced what this reaches yet, so treat the blast radius as unknown — " +
			"connect your cloud account and we will map it."
	}
}

// headline is the one line someone reads in a list. It leads with CONSEQUENCE where the graph proved
// one, because "anyone can read your customer table" moves a founder and "SQL Injection (CWE-89)"
// does not.
func headline(c class, subject string, ctx Context) string {
	// Prefer the caller's asset label, then the subject the source itself named, and only then a
	// generic. "your app" is a last resort, not a default: someone running six services cannot act on
	// it, and we usually know better.
	where := strings.TrimSpace(ctx.AssetLabel)
	if where == "" {
		where = strings.TrimSpace(subject)
	}
	if where == "" {
		where = "your app"
	}
	if len(ctx.Reaches) > 0 {
		return c.headlineVerb + " " + where + " — and it reaches " + ctx.Reaches[0] + "."
	}
	return c.headlineVerb + " " + where + "."
}

// urgency grades how soon, and returns the facts behind the grade.
//
// The ladder is evidence-ordered, and severity ALONE never reaches "now": a scanner's opinion that
// something is critical is not evidence that anyone is attacking you, and treating it as such is
// exactly what trained everyone to ignore the word.
func urgency(f types.Finding, ctx Context) (Urgency, []string) {
	var because []string

	if ctx.UnderAttack {
		because = append(because, "we are seeing this endpoint attacked in production right now")
	}
	kev := f.ThreatIntel != nil && f.ThreatIntel.KEV != nil && f.ThreatIntel.KEV.Listed
	if kev {
		because = append(because, "this vulnerability is on CISA's actively-exploited list — attackers are using it in the wild today")
	}
	// An ASSESSOR's "verified" means "I read the configuration and it says this" — it is certainty
	// about a fact, not evidence that anyone can exploit it. A pentest tool's "verified" means the
	// exploit ran and worked. Conflating them put "Fix today — we proved it is exploitable" on a
	// Vercel setting nobody had attacked, which is the precise overstatement the urgency ladder
	// exists to prevent. Certainty is not urgency.
	proven := f.VerificationStatus == types.VerificationVerified && !isAssessor(f.Tool)
	if proven {
		because = append(because, "we proved it is exploitable on your system, not just possible")
	}
	if len(because) > 0 {
		return UrgencyNow, because
	}

	reachesCrown := len(ctx.Reaches) > 0
	highEPSS := f.ThreatIntel != nil && f.ThreatIntel.EPSS != nil && f.ThreatIntel.EPSS.Score >= 0.1
	exploitable := f.Exploitability != nil && f.Exploitability.Score >= 7
	if highEPSS {
		because = append(because, "it has a raised chance of being exploited in the next 30 days")
	}
	if exploitable {
		because = append(because, "it is reachable without credentials")
	}
	if reachesCrown {
		because = append(because, "it leads to "+ctx.Reaches[0])
	}
	if len(because) >= 2 || (reachesCrown && sevAtLeast(f.Severity, types.SeverityHigh)) {
		return UrgencyThisWeek, because
	}

	if sevAtLeast(f.Severity, types.SeverityHigh) {
		because = append(because, "it is a serious class of bug, though nothing indicates it is being exploited")
		return UrgencyThisMonth, because
	}
	if len(because) > 0 {
		return UrgencyThisMonth, because
	}
	return UrgencyWhenever, nil
}

func sevAtLeast(s, min types.Severity) bool { return s.Rank() >= min.Rank() }

// ── class templates ──────────────────────────────────────────────────────────────────────────────

type class struct {
	headlineVerb string // completes "<verb> your app"
	what         string
	fix          string
}

// classify maps a finding to its plain-English class, by CWE first (precise) then rule-id keywords
// (broad). An unrecognised class falls back to the tool's own words rather than a confident-sounding
// template — inventing an explanation for a class we do not model would be exactly the false
// confidence the rest of the engine refuses.
func classify(f types.Finding) (class, string) {
	// An ASSESSOR (vercelposture, dataplatform, deviceposture, …) already writes a plain-English
	// title and description aimed at this exact reader. Re-classifying it is not just redundant, it is
	// actively wrong: keyword-matching "production-secret-in-preview" landed on the hardcoded-credential
	// template and told someone to "move it to your secret manager" — it is already in one, scoped too
	// broadly. A wrong diagnosis produces a wrong fix, which is worse than no translation at all.
	if isAssessor(f.Tool) && strings.TrimSpace(f.Description) != "" {
		verb, subj := assessorVerb(f.Title)
		return class{headlineVerb: verb, what: f.Description, fix: assessorFix(f.Description)}, subj
	}
	for _, cwe := range f.CWE {
		if c, ok := cweClasses[normalizeCWE(cwe)]; ok {
			return c, ""
		}
	}
	hay := strings.ToLower(f.RuleID + " " + f.Title)
	for _, kc := range keywordClasses {
		for _, k := range kc.keys {
			if strings.Contains(hay, k) {
				return kc.c, ""
			}
		}
	}
	return fallbackClass(f), ""
}

// fallbackClass reports what the tool said, flagged as un-translated. Honest degradation: the reader
// gets the raw title and knows it is raw, instead of a fluent paragraph we made up.
func fallbackClass(f types.Finding) class {
	title := strings.TrimSpace(f.Title)
	if title == "" {
		title = f.RuleID
	}
	what := title
	if d := strings.TrimSpace(f.Description); d != "" {
		what = title + ". " + d
	}
	return class{
		headlineVerb: "A security issue was found in",
		what:         what + " (this is the scanner's own wording — we do not have a plain-English translation for this class yet).",
		fix:          "Review the technical detail below, or ask the AI security engineer to investigate this one.",
	}
}

func normalizeCWE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "CWE-") {
		s = "CWE-" + s
	}
	return s
}

var cweClasses = map[string]class{
	"CWE-89": {"Anyone can read or change the database behind",
		"A place where your app builds a database query out of text a visitor typed. By typing the right thing, someone can make the database run their query instead of yours — reading, changing or deleting any data in it.",
		"Use parameterised queries (bound parameters) instead of building SQL by joining strings. Most ORMs do this by default; the risk is the hand-written query."},
	"CWE-79": {"Someone can run their own code in the browser of anyone using",
		"Your app puts text a visitor supplied straight into a page without neutralising it, so an attacker can make a victim's browser run their script — stealing that person's session and acting as them.",
		"Escape user-supplied values on output, and set a Content-Security-Policy. Modern templating escapes by default; the risk is anywhere you bypass it."},
	"CWE-78": {"Someone can run commands on the server behind",
		"Your app passes text a visitor supplied into a shell command, so an attacker can append their own command and run it on your server with your app's privileges.",
		"Do not build shell commands from user input. Call the program directly with an argument list, never through a shell."},
	"CWE-22": {"Someone can read files off the server behind",
		"A file path is built from something a visitor supplied, so an attacker can walk out of the intended folder (../) and read files you never meant to serve — config, keys, source.",
		"Resolve the final path and verify it is still inside the intended directory before opening it. Reject any path containing traversal sequences."},
	"CWE-918": {"Your server can be tricked into making requests on an attacker's behalf from",
		"An attacker controls a URL your server fetches, so they can make your server call internal addresses they cannot reach themselves — including cloud metadata endpoints that hand out credentials.",
		"Allow-list the hosts your server may fetch, resolve the DNS name and re-check the resolved IP is not private, and block redirects to internal ranges."},
	"CWE-502": {"Someone can run code on the server behind",
		"Your app turns attacker-supplied data back into objects (deserialisation). Crafted input can construct objects that execute code as they are built.",
		"Do not deserialise untrusted data into arbitrary types. Use a data-only format (JSON to a known struct) and reject unexpected types."},
	"CWE-798": {"A password or key is written into the source of",
		"A credential is hard-coded in the codebase. Anyone with repository access — including anyone who ever forked, cloned or saw a leak — has it, and rotating it means a code change.",
		"Move it to your secret manager or environment, then ROTATE it: assume the old value is compromised, because it is in git history."},
	"CWE-306": {"An endpoint is exposed with no login on",
		"Something that should require authentication does not, so anyone who finds the URL can use it.",
		"Put the endpoint behind your existing auth middleware and add a test that an anonymous request is rejected."},
	"CWE-639": {"One customer can read another customer's data on",
		"The app trusts an id from the request to decide which record to return, without checking the logged-in user owns it. Change the id, get someone else's data.",
		"Check ownership on every read and write: the record's owner must match the session's user. Do not rely on the id being unguessable."},
	"CWE-200": {"Information you did not mean to publish is exposed on",
		"An endpoint or response leaks internal detail — stack traces, versions, internal paths or another user's fields — that helps an attacker plan.",
		"Return generic errors to clients, log the detail server-side, and trim API responses to the fields the caller needs."},
	"CWE-1104": {"A dependency with a known vulnerability is shipping in",
		"One of your third-party packages has a publicly-known vulnerability. The code is yours to ship, so the risk is yours even though the bug is not.",
		"Upgrade the package to the fixed version. If no fix exists, check whether your code reaches the vulnerable function before treating it as urgent."},
	"CWE-319": {"Data travels unencrypted to or from",
		"Traffic is sent without TLS, so anyone on the network path can read or alter it.",
		"Force HTTPS, redirect plaintext, and turn on HSTS so browsers refuse to downgrade."},
}

var keywordClasses = []struct {
	keys []string
	c    class
}{
	{[]string{"sql-injection", "sqli"}, cweClasses["CWE-89"]},
	{[]string{"xss", "cross-site-script"}, cweClasses["CWE-79"]},
	{[]string{"ssrf"}, cweClasses["CWE-918"]},
	{[]string{"traversal", "lfi"}, cweClasses["CWE-22"]},
	{[]string{"secret", "credential", "api-key", "hardcoded"}, cweClasses["CWE-798"]},
	{[]string{"idor", "bola", "object-level"}, cweClasses["CWE-639"]},
	{[]string{"public-bucket", "public-access", "publicly-accessible", "anonymous"}, class{
		"Data is readable by the public in",
		"A storage location is open to anyone on the internet. No exploit is needed — someone just has to find the address, and scanners find these constantly.",
		"Turn off public access on the bucket or object, then check the access logs for who already read it.",
	}},
	{[]string{"mfa", "2fa", "multi-factor"}, class{
		"Accounts can be taken over with just a password on",
		"An account with meaningful access has no second factor, so a leaked or guessed password is enough to get in as them.",
		"Enforce MFA for the account, and require it org-wide so this cannot recur.",
	}},
	{[]string{"dmarc", "spf", "dkim"}, class{
		"Anyone can send email pretending to be",
		"Your domain does not tell receiving mail servers how to detect forgeries, so an attacker can email your customers or staff as you.",
		"Publish the DNS record we generated for you. Start in monitor mode, then tighten to reject.",
	}},
	{[]string{"tls", "certificate", "ssl", "https"}, cweClasses["CWE-319"]},
}

// humanList joins items the way a person writes them: "a, b and c".
func humanList(items []string) string {
	c := append([]string(nil), items...)
	sort.Strings(c)
	switch len(c) {
	case 0:
		return ""
	case 1:
		return c[0]
	case 2:
		return c[0] + " and " + c[1]
	default:
		return strings.Join(c[:len(c)-1], ", ") + " and " + c[len(c)-1]
	}
}

// assessorTools are the packages that produce customer-ready prose by design — they are written for a
// non-security reader already, so translating them again can only lose fidelity or invent a class.
var assessorTools = map[string]bool{
	"vercelposture": true, "dataplatform": true, "deviceposture": true, "tprm": true,
	"osint": true, "sspm": true, "operate": true, "clouddrift": true, "identitythreat": true,
}

func isAssessor(tool string) bool { return assessorTools[strings.ToLower(strings.TrimSpace(tool))] }

// assessorVerb splits the assessor's own title into the headline verb and the SUBJECT it names, so the
// headline can say which project rather than a generic one.
//
// It returns the subject instead of discarding it because dropping it and then substituting "your app"
// was strictly worse than either: a customer with six Vercel projects was told "Preview deployments are
// public — your app", when the assessor had written "…: acme-web" and we threw the name away. Falls
// back to the whole title rather than risking an empty headline.
func assessorVerb(title string) (verb, subject string) {
	t := strings.TrimSpace(title)
	if i := strings.LastIndex(t, ": "); i > 0 {
		if head := strings.TrimSpace(t[:i]); head != "" {
			return head + " —", strings.TrimSpace(t[i+2:])
		}
	}
	if t == "" {
		return "A security issue was found in", ""
	}
	return t + " —", ""
}

// assessorFix pulls the remediation sentence out of the assessor's description. Assessors end with the
// action ("Turn on Deployment Protection…", "Scope them to Production only…"), so the last sentence is
// the instruction. Empty when there is no clear one — better silent than a fabricated instruction.
func assessorFix(desc string) string {
	d := strings.TrimSpace(desc)
	if d == "" {
		return ""
	}
	parts := strings.Split(d, ". ")
	last := strings.TrimSpace(parts[len(parts)-1])
	// A trailing fragment that is not an instruction is worse than nothing: it reads as advice while
	// telling the reader to do something they cannot act on.
	if len(last) < 15 {
		return ""
	}
	return last
}
