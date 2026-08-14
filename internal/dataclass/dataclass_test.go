package dataclass

import (
	"strings"
	"testing"
)

func hasClass(r Result, c Class) *Match {
	for i := range r.Matches {
		if r.Matches[i].Class == c {
			return &r.Matches[i]
		}
	}
	return nil
}

// ── THE REFUSAL THAT DEFINES THE PACKAGE ─────────────────────────────────────────────────────────
//
// A table's NAME is not evidence of its contents. This is the same refusal dataplatform makes, and a
// classifier that broke it would undermine the very flag it feeds.
func TestClassify_NeverClassifiesFromTheObjectName(t *testing.T) {
	// Every signal is in the object name; the columns are innocuous and hold innocuous values.
	r := Classify(Object{
		Name: "customer_pii_ssn_creditcard_health_passwords",
		Columns: []Column{
			{Name: "id", Values: []string{"1", "2", "3"}},
			{Name: "count", Values: []string{"10", "20"}},
		},
	})
	if r.Sensitive() {
		t.Errorf("classified from the object NAME alone: %v", r.Matches)
	}
}

// ── VALUE OUTRANKS NAME ──────────────────────────────────────────────────────────────────────────

// A column whose values ARE SSNs is Confirmed; a column merely NAMED ssn with no values is Suspected.
// A caller escalating a crown jewel must be able to tell proof from a hint.
func TestClassify_ValueEvidenceIsConfirmedNameOnlyIsSuspected(t *testing.T) {
	confirmed := Classify(Object{Name: "t", Columns: []Column{
		{Name: "national_number", Values: []string{"123-45-6789", "078-05-1120"}},
	}})
	if m := hasClass(confirmed, ClassPII); m == nil || m.Confidence != Confirmed {
		t.Fatalf("real SSN values were not Confirmed PII: %+v", confirmed.Matches)
	}

	suspected := Classify(Object{Name: "t", Columns: []Column{{Name: "ssn"}}}) // named, no values
	if m := hasClass(suspected, ClassPII); m == nil || m.Confidence != Suspected {
		t.Fatalf("a column named ssn with no values should be Suspected, got %+v", suspected.Matches)
	}
}

// When both name and value agree on the same column, it collapses to ONE Confirmed match — the name
// hint must not survive as a second, weaker row.
func TestClassify_NameAndValueAgreeCollapseToConfirmed(t *testing.T) {
	r := Classify(Object{Name: "t", Columns: []Column{
		{Name: "ssn", Values: []string{"123-45-6789"}},
	}})
	n := 0
	for _, m := range r.Matches {
		if m.Class == ClassPII && m.Column == "ssn" {
			n++
			if m.Confidence != Confirmed {
				t.Errorf("agreeing name+value was not Confirmed: %+v", m)
			}
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one PII match for the ssn column, got %d", n)
	}
}

// ── STRUCTURE IS CHECKED, NOT JUST SHAPE ─────────────────────────────────────────────────────────
//
// This is the line between DSPM and a noise generator. A 16-digit ORDER NUMBER is not a card; a
// nine-digit reserved SSN is not an SSN.

func TestClassify_CardNumberRequiresLuhn(t *testing.T) {
	// 4111111111111111 is a Luhn-valid test PAN; 4111111111111112 is not.
	good := Classify(Object{Name: "t", Columns: []Column{{Name: "col", Values: []string{"4111111111111111"}}}})
	if hasClass(good, ClassPCI) == nil {
		t.Error("a Luhn-valid card number was not classified PCI")
	}
	bad := Classify(Object{Name: "t", Columns: []Column{{Name: "order_no", Values: []string{"4111111111111112", "1234567812345678"}}}})
	if hasClass(bad, ClassPCI) != nil {
		t.Error("a 16-digit non-Luhn number was miscalled a card — this is exactly the DLP false positive to avoid")
	}
}

func TestClassify_SSNRejectsReservedRanges(t *testing.T) {
	for _, invalid := range []string{"000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"} {
		r := Classify(Object{Name: "t", Columns: []Column{{Name: "num", Values: []string{invalid}}}})
		if hasClass(r, ClassPII) != nil {
			t.Errorf("%q is a reserved/invalid SSN but was classified PII", invalid)
		}
	}
	valid := Classify(Object{Name: "t", Columns: []Column{{Name: "num", Values: []string{"123-45-6789"}}}})
	if hasClass(valid, ClassPII) == nil {
		t.Error("a valid SSN was not classified")
	}
}

// ── DETECTOR COVERAGE ────────────────────────────────────────────────────────────────────────────

func TestClassify_DetectsSecretsAndAuthByValue(t *testing.T) {
	cases := []struct {
		val  string
		want Class
	}{
		{"AKIAIOSFODNN7EXAMPLE", ClassSecret},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", ClassSecret},
		{"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", ClassAuth},
		{"alice@example.com", ClassPII},
	}
	for _, tc := range cases {
		r := Classify(Object{Name: "t", Columns: []Column{{Name: "col", Values: []string{tc.val}}}})
		if hasClass(r, tc.want) == nil {
			t.Errorf("value %q was not classified %s: %+v", tc.val, tc.want, r.Matches)
		}
	}
}

func TestClassify_DetectsPrivateKeyByValue(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEp...\n-----END RSA PRIVATE KEY-----"
	r := Classify(Object{Name: "t", Columns: []Column{{Name: "blob", Values: []string{pem}}}})
	if hasClass(r, ClassSecret) == nil {
		t.Error("a PEM private key was not classified as a secret")
	}
}

// ── HYGIENE ──────────────────────────────────────────────────────────────────────────────────────

// A clean object is silent — no classes, not "probably fine". This is what makes a positive mean
// something.
func TestClassify_CleanObjectYieldsNothing(t *testing.T) {
	r := Classify(Object{Name: "orders", Columns: []Column{
		{Name: "order_id", Values: []string{"1001", "1002"}},
		{Name: "quantity", Values: []string{"3", "7"}},
		{Name: "status", Values: []string{"shipped", "pending"}},
	}})
	if r.Sensitive() {
		t.Errorf("a clean table produced classifications: %+v", r.Matches)
	}
	if r.HighestConfidence != "" {
		t.Errorf("clean object reported a confidence: %q", r.HighestConfidence)
	}
}

// Every match must be auditable — it names the column and the signal — and must never echo a raw value,
// or the finding would leak the data it is about.
func TestClassify_EvidenceIsAuditableAndLeaksNoValue(t *testing.T) {
	ssn := "123-45-6789"
	r := Classify(Object{Name: "t", Columns: []Column{{Name: "national_number", Values: []string{ssn}}}})
	m := hasClass(r, ClassPII)
	if m == nil {
		t.Fatal("no PII match")
	}
	if m.Column != "national_number" {
		t.Errorf("evidence does not name the column: %q", m.Column)
	}
	if m.Evidence == "" {
		t.Error("match carries no human-checkable evidence")
	}
	if strings.Contains(m.Evidence, ssn) {
		t.Errorf("the evidence string leaked the raw value: %q", m.Evidence)
	}
}

func TestClassify_HandlesEmptyAndBlankInput(t *testing.T) {
	if Classify(Object{}).Sensitive() {
		t.Error("empty object was classified")
	}
	if Classify(Object{Name: "t", Columns: []Column{{Name: "  ", Values: []string{"", "  "}}}}).Sensitive() {
		t.Error("blank column/values were classified")
	}
}

// The Sensitive() bit is exactly what the graph's crown-jewel test consumes, so pin it.
func TestResult_SensitiveReflectsClasses(t *testing.T) {
	if (Result{}).Sensitive() {
		t.Error("empty result reported sensitive")
	}
	if !(Result{Classes: []Class{ClassPII}}).Sensitive() {
		t.Error("a result with a class reported not-sensitive")
	}
}
