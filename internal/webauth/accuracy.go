package webauth

// This file is the login-wall accuracy harness — a labeled corpus of HTTP responses + a scorer
// that MEASURES IsLoginWall's precision/recall (the FN gap closed in #325 + its FP guards). Same
// sensitivity↔specificity discipline as the per-asset benches (CLAUDE.md §14.1.1). The login-wall
// signal is the FN guard against silently scanning logged-out, so both axes matter: a missed wall
// = a scan trusted while logged out; a false wall = a needless re-auth / aborted scan.

// LabeledResponse is one HTTP response with its ground-truth: is this a login wall (session
// missing/expired) or a normal authenticated response?
type LabeledResponse struct {
	Name     string
	Status   int
	Location string
	Body     string
	IsWall   bool
}

// WallScore is the confusion matrix over the corpus.
type WallScore struct{ TP, FP, FN, TN int }

// Recall = TP / (TP + FN) — of the real login walls, how many were detected (the FN axis).
func (s WallScore) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP) — of the detected walls, how many were real (the FP axis).
func (s WallScore) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreLoginWall runs IsLoginWall over each labeled response and tallies the confusion matrix.
func ScoreLoginWall(cases []LabeledResponse, f LoginFlow) WallScore {
	var s WallScore
	for _, c := range cases {
		switch got := IsLoginWall(c.Status, c.Location, c.Body, f); {
		case c.IsWall && got:
			s.TP++
		case c.IsWall && !got:
			s.FN++
		case !c.IsWall && got:
			s.FP++
		default:
			s.TN++
		}
	}
	return s
}

// LoginWallCorpus is the built-in labeled corpus: real login walls across every detection path
// (status, redirect, inline password form, JSON auth-error) + normal authenticated responses
// incl. the FP traps (HTML prose mentioning "unauthorized", a non-auth JSON error, a JSON body
// with no error key, a redirect to a non-login page).
func LoginWallCorpus() []LabeledResponse {
	return []LabeledResponse{
		// --- real login walls ---
		{"401", 401, "", "", true},
		{"403", 403, "", "", true},
		{"redirect_to_login", 302, "https://app.example.com/login?next=/x", "", true},
		{"redirect_to_sso", 302, "https://sso.example.com/auth", "", true},
		{"inline_password_form", 200, "", `<form><input type="password" name="pw"></form>`, true},
		{"json_unauthorized", 200, "", `{"error":"unauthorized"}`, true},
		{"json_auth_required", 200, "", `{"message":"Authentication required"}`, true},
		{"json_token_expired", 401, "", `{"code":"token_expired"}`, true},
		{"json_drf", 200, "", `{"detail":"Authentication credentials were not provided."}`, true},

		// --- normal authenticated responses (must NOT be a wall) ---
		{"authed_html", 200, "", `<html><body><h1>Welcome, Alice</h1><a href="/logout">Sign out</a></body></html>`, false},
		{"authed_json", 200, "", `{"status":"ok","user":"alice"}`, false},
		{"redirect_to_dashboard", 302, "https://app.example.com/dashboard", "", false},
		{"html_mentions_unauthorized", 200, "", `<html><body>How to handle a 401 Unauthorized error in your API.</body></html>`, false},
		{"json_non_auth_error", 200, "", `{"error":"validation failed","field":"email"}`, false},
		{"json_no_error_key", 200, "", `{"data":{"article":"a guide to unauthorized access"}}`, false},
	}
}
