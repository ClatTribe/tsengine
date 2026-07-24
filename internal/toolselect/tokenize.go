package toolselect

import "strings"

// tokenize lowercases, splits on non-alphanumerics, drops stopwords + very short tokens, and applies a
// tiny domain-aware normalization so query wording matches tool wording (e.g. "authorization" ~ "authz",
// "sql injection" ~ "sqli"). Deterministic and dependency-free — no stemmer/embeddings needed for a
// catalog of a few dozen tools; the curated Tags carry the semantic bridge where prose won't.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 3 || stopwords[f] {
			continue
		}
		if norm, ok := synonym[f]; ok {
			f = norm
		}
		out = append(out, f)
	}
	return out
}

// synonym folds common query phrasings onto the token a tool description/tag uses. Kept small and
// unambiguous — each entry is a genuine alias in this security domain, never a lossy stem.
var synonym = map[string]string{
	"authorization":   "authz",
	"authorisation":   "authz",
	"idor":            "bola",
	"privilege":       "privesc",
	"escalation":      "privesc",
	"credential":      "creds",
	"credentials":     "creds",
	"password":        "creds",
	"passwords":       "creds",
	"injection":       "inject",
	"injections":      "inject",
	"tampering":       "tamper",
	"tampered":        "tamper",
	"vulnerability":   "vuln",
	"vulnerabilities": "vuln",
	"remediation":     "fix",
	"remediate":       "fix",
	"permission":      "iam",
	"permissions":     "iam",
	"identity":        "iam",
}

var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
	"you": true, "your": true, "are": true, "not": true, "but": true, "its": true,
	"from": true, "into": true, "when": true, "then": true, "than": true, "onto": true,
	"via": true, "per": true, "any": true, "all": true, "one": true, "use": true,
	"run": true, "get": true, "set": true, "put": true, "add": true, "new": true,
	"has": true, "have": true, "will": true, "can": true, "may": true, "must": true,
	"a": true, "an": true, "to": true, "of": true, "in": true, "on": true, "is": true,
	"it": true, "or": true, "as": true, "at": true, "by": true, "be": true, "do": true,
}
