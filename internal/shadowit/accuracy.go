package shadowit

// This file is the shadow-IT scope-classification accuracy harness — a labeled corpus + a scorer
// that MEASURES the sensitive-scope precision/recall the taxonomy claims (the FN expansion + the
// identity-scope FP guard). Same sensitivity↔specificity discipline as the per-asset benches
// (CLAUDE.md §14.1.1), for this host-side deterministic classifier.

// LabeledScope is one OAuth scope with its ground-truth sensitivity.
type LabeledScope struct {
	Scope     string
	Sensitive bool
}

// ScopeScore is the confusion matrix over a labeled scope corpus.
type ScopeScore struct{ TP, FP, FN, TN int }

// Recall = TP / (TP + FN) — of the truly-sensitive scopes, how many were flagged (the FN axis).
func (s ScopeScore) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP) — of the flagged scopes, how many were truly sensitive (the FP axis).
func (s ScopeScore) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreScopes runs isSensitive over each labeled scope and tallies the confusion matrix.
func ScoreScopes(cases []LabeledScope) ScopeScore {
	var s ScopeScore
	for _, c := range cases {
		switch got := isSensitive(c.Scope); {
		case c.Sensitive && got:
			s.TP++
		case c.Sensitive && !got:
			s.FN++
		case !c.Sensitive && got:
			s.FP++
		default:
			s.TN++
		}
	}
	return s
}

// ScopeCorpus is the built-in labeled scope corpus: high-risk scopes across Google / M365 /
// GitHub / Slack (must be flagged → recall) + identity-only and narrow non-sensitive scopes that
// must NOT be flagged (→ precision, incl. the OIDC `email` / `user:email` FP traps).
func ScopeCorpus() []LabeledScope {
	sensitive := []string{
		// Google
		"https://mail.google.com/", "https://www.googleapis.com/auth/drive",
		"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/bigquery",
		"https://www.googleapis.com/auth/admin.directory.user",
		// M365
		"Mail.Read", "Files.ReadWrite.All", "User.ReadWrite.All", "Sites.FullControl.All",
		"Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
		// GitHub
		"repo", "admin:org", "write:org", "delete_repo", "admin:repo_hook", "workflow",
		// Slack
		"channels:history", "im:history", "mpim:history", "users:read", "chat:write", "files:read",
	}
	benign := []string{
		// OIDC / identity (the FP traps — `email` and `user:email` contain the substring "mail")
		"openid", "profile", "email", "user:email", "users:read.email",
		"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",
		// narrow, non-sensitive scopes that match no high-risk token
		"read:user", "commands", "reactions:read", "team",
	}
	out := make([]LabeledScope, 0, len(sensitive)+len(benign))
	for _, s := range sensitive {
		out = append(out, LabeledScope{Scope: s, Sensitive: true})
	}
	for _, s := range benign {
		out = append(out, LabeledScope{Scope: s, Sensitive: false})
	}
	return out
}
