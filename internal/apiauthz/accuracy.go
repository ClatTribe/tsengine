package apiauthz

// This file is the authz-predicate accuracy harness — a labeled corpus of (request response pairs)
// + a scorer that MEASURES the BOLA / BFLA / mass-assignment predicates' precision/recall. The
// no-FP bar (a confirmed finding is `verification: verified`) makes PRECISION the headline: a
// false bypass is a falsely-confident "verified" exploit. Same discipline as the per-asset benches
// (§14.1.1); offline (no live prober).

// LabeledAuthzCase is one predicate scenario. For BOLA/BFLA, A is the victim baseline and B the
// attacker response; for mass_assignment, A is the write response and B the read-back. ExpectBypass
// is the ground truth.
type LabeledAuthzCase struct {
	Name         string
	Op           Operation
	A, B         Response
	ExpectBypass bool
}

// AuthzScore is the confusion matrix over the corpus.
type AuthzScore struct{ TP, FP, FN, TN int }

// Recall = TP / (TP + FN) — of the real bypasses, how many were detected.
func (s AuthzScore) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Precision = TP / (TP + FP) — of the flagged bypasses, how many were real (the no-FP bar).
func (s AuthzScore) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// ScoreAuthz runs the right predicate per case (Evaluate for BOLA/BFLA, evaluateMassAssignment for
// mass_assignment) and tallies the confusion matrix against ExpectBypass.
func ScoreAuthz(cases []LabeledAuthzCase) AuthzScore {
	var s AuthzScore
	for _, c := range cases {
		var v Verdict
		if c.Op.Class == ClassMass {
			v = evaluateMassAssignment(c.Op, c.A, c.B)
		} else {
			v = Evaluate(AuthzTest{Op: c.Op}, c.A, c.B)
		}
		switch {
		case c.ExpectBypass && v.Bypassed:
			s.TP++
		case c.ExpectBypass && !v.Bypassed:
			s.FN++
		case !c.ExpectBypass && v.Bypassed:
			s.FP++
		default:
			s.TN++
		}
	}
	return s
}

// AuthzCorpus is the built-in labeled corpus: real bypasses across BOLA / BFLA / mass-assignment
// (must fire → recall) + secure outcomes and the FP traps that must NOT (→ precision / no-FP bar).
func AuthzCorpus() []LabeledAuthzCase {
	bola := Operation{Method: "GET", URL: "/invoices/42", Class: ClassBOLA, Marker: "victim@acme.com"}
	bolaNoMark := Operation{Method: "GET", URL: "/invoices/42", Class: ClassBOLA}
	bfla := Operation{Method: "DELETE", URL: "/admin/users/7", Class: ClassBFLA}
	mass := Operation{Method: "PATCH", URL: "/users/me", Class: ClassMass, Marker: "admin"}

	return []LabeledAuthzCase{
		// --- real bypasses (must fire) ---
		{"bola_marker_leak", bola, Response{200, "victim@acme.com"}, Response{200, "...victim@acme.com..."}, true},
		{"bola_body_equality", bolaNoMark, Response{200, `{"id":42,"owner":"alice"}`}, Response{200, `{"id":42,"owner":"alice"}`}, true},
		{"bfla_undenied", bfla, Response{200, "deleted"}, Response{200, "deleted"}, true},
		{"mass_field_persisted", mass, Response{200, "{}"}, Response{200, `{"name":"me","role":"admin"}`}, true},

		// --- secure outcomes (must NOT fire) ---
		{"bola_denied_403", bola, Response{200, "victim@acme.com"}, Response{403, ""}, false},
		{"bola_notfound_404", bola, Response{200, "victim@acme.com"}, Response{404, ""}, false},
		{"bfla_denied_403", bfla, Response{200, "deleted"}, Response{403, ""}, false},

		// --- FP traps (must NOT fire — the no-FP bar) ---
		{"bola_2xx_no_data", bola, Response{200, "victim@acme.com"}, Response{200, "access denied"}, false},              // 2xx but the marker isn't present
		{"bola_trivial_body", bolaNoMark, Response{200, "[]"}, Response{200, "[]"}, false},                               // equal but trivial body
		{"bola_different_body", bolaNoMark, Response{200, `{"owner":"alice"}`}, Response{200, `{"owner":"bob"}`}, false}, // attacker got a DIFFERENT object
		{"mass_field_ignored", mass, Response{200, "{}"}, Response{200, `{"name":"me","role":"user"}`}, false},           // server ignored the privileged field
		{"mass_write_rejected", mass, Response{403, ""}, Response{200, `{"role":"admin"}`}, false},                       // the write was rejected
	}
}
