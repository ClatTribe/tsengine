// Package dataclass is DATA CLASSIFICATION — deciding what KIND of data an object holds by looking at
// the data, not at its name.
//
// WHY IT EXISTS. Across the engine, a data store's sensitivity (cloudgraph.Node.Sensitive,
// estategraph.SensHigh, dataplatform's declared flag) is only ever COPIED THROUGH from an upstream
// source or declared by the customer. Nothing discovers it. So every attack path in the product ends
// at a crown jewel that was ASSERTED, never proven: "this bucket is sensitive" rests on a checkbox, and
// a checkbox nobody ticked reads as safe. The whole graph's terminal node is taken on trust.
//
// Classify closes that: given an object's columns (names, and optionally sampled values) it returns the
// data classes actually present, each with the EVIDENCE that found it. A discovered classification is
// what lets a crown jewel be a fact rather than a claim.
//
// GROUNDED (§10), and the refusals are the whole point — a classifier that cries wolf is one whose
// output nobody trusts, and a false NEGATIVE hides a breach:
//
//   - NEVER FROM THE NAME OF THE OBJECT. A table called "customers" is not evidence it holds customer
//     data; dataplatform already refuses this, and so must the classifier that would otherwise
//     undermine it. Only COLUMN names and VALUES are evidence.
//   - A VALUE SIGNAL OUTRANKS A NAME SIGNAL. A column literally called "ssn" is a hint; a column whose
//     values are shaped like SSNs is proof. When both agree the classification is Confirmed; a name
//     alone is Suspected, and the caller can treat the two differently.
//   - STRUCTURE IS CHECKED, NOT JUST SHAPE. A 16-digit number is not a card number unless it passes
//     Luhn; a nine-digit number is not an SSN if it is in a reserved range. Matching a regex is where a
//     naive DLP tool stops and starts generating noise.
//   - IT REPORTS WHAT MATCHED. Every classification names the column and the signal, so a human can
//     check it. A verdict you cannot audit is a guess with a label.
//
// Deterministic, dependency-free, sample-based (metadata + a bounded sample — never the full dataset,
// ADR-0002's "metadata, never the data itself" rule). A clean object yields nothing.
package dataclass

import (
	"regexp"
	"sort"
	"strings"
)

// Class is a category of sensitive data.
type Class string

const (
	ClassPII    Class = "pii"    // personal identifiers: SSN, DOB, phone, email, address
	ClassPHI    Class = "phi"    // protected health information
	ClassPCI    Class = "pci"    // cardholder data
	ClassSecret Class = "secret" // credentials, API keys, private keys
	ClassAuth   Class = "auth"   // password hashes, tokens at rest
)

// Confidence separates a value-proven classification from a name-only suspicion. The distinction is
// load-bearing: a caller escalating a crown jewel should treat Confirmed as fact and Suspected as a
// prompt to sample, never collapse them.
type Confidence string

const (
	// Suspected: a COLUMN NAME matched, but no value confirmed it (or no values were sampled). A strong
	// hint, not proof — the column could be mislabelled or empty.
	Suspected Confidence = "suspected"
	// Confirmed: actual VALUES matched the class's structure (and passed any structural check). This is
	// the data itself testifying.
	Confirmed Confidence = "confirmed"
)

// Column is one field of a data object: its name and, optionally, a bounded sample of its values.
type Column struct {
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"` // a SAMPLE — never the full column
}

// Object is a data object to classify (a table, a collection, a file). Note there is NO place to
// declare sensitivity here: the whole point is to DISCOVER it. The object's own Name is deliberately
// NOT used as evidence.
type Object struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}

// Match is one piece of evidence: a class found in a column, and how.
type Match struct {
	Class      Class      `json:"class"`
	Column     string     `json:"column"`
	Confidence Confidence `json:"confidence"`
	// Evidence is the human-checkable reason — "column named 'ssn'" or "3 of 10 sampled values are
	// SSN-shaped (Luhn/range-checked)". Never a raw value: the finding must be auditable without
	// leaking the data it is about.
	Evidence string `json:"evidence"`
}

// Result is the classification of one object.
type Result struct {
	Object  string  `json:"object"`
	Classes []Class `json:"classes"` // the distinct classes present, sorted
	Matches []Match `json:"matches"` // the evidence, one per (class, column)
	// HighestConfidence is Confirmed if any match is value-proven, else Suspected, else "".
	HighestConfidence Confidence `json:"highest_confidence,omitempty"`
}

// Sensitive reports whether the object holds any classified data at all — the one-bit answer the graph's
// crown-jewel test needs.
func (r Result) Sensitive() bool { return len(r.Classes) > 0 }

// Classify inspects an object and returns the sensitive-data classes it actually contains.
//
// Empty when nothing matched — a clean object is silent, never "probably fine".
func Classify(o Object) Result {
	res := Result{Object: o.Name}
	byKey := map[string]Match{} // dedupe to one match per (class, column), keeping the strongest

	record := func(m Match) {
		key := string(m.Class) + "\x00" + m.Column
		if cur, ok := byKey[key]; ok && cur.Confidence == Confirmed {
			return // a value-proven match already stands for this (class, column); a name hint can't beat it
		}
		byKey[key] = m
	}

	for _, col := range o.Columns {
		name := strings.TrimSpace(col.Name)
		lname := strings.ToLower(name)

		// 1) VALUE evidence — the strongest, so gather it first. A structural check (Luhn, range) gates
		//    every value detector, because a shape match alone is how DLP tools generate their noise.
		for _, d := range valueDetectors {
			hits, sampled := d.count(col.Values)
			if hits > 0 {
				record(Match{
					Class: d.class, Column: name, Confidence: Confirmed,
					Evidence: plural(hits, "value") + " of " + itoa(sampled) + " sampled match " + d.label,
				})
			}
		}

		// 2) NAME evidence — a suspicion, recorded only where a value match did not already confirm the
		//    same class for this column. A name is a hint about intent; it is not the data.
		if name == "" {
			continue
		}
		for _, nd := range nameDetectors {
			if nd.matches(lname) {
				record(Match{
					Class: nd.class, Column: name, Confidence: Suspected,
					Evidence: "column named '" + name + "' suggests " + string(nd.class),
				})
			}
		}
	}

	classes := map[Class]bool{}
	for _, m := range byKey {
		res.Matches = append(res.Matches, m)
		classes[m.Class] = true
		if m.Confidence == Confirmed {
			res.HighestConfidence = Confirmed
		}
	}
	if res.HighestConfidence == "" && len(res.Matches) > 0 {
		res.HighestConfidence = Suspected
	}
	for c := range classes {
		res.Classes = append(res.Classes, c)
	}
	sort.Slice(res.Classes, func(i, j int) bool { return res.Classes[i] < res.Classes[j] })
	sort.Slice(res.Matches, func(i, j int) bool {
		if res.Matches[i].Class != res.Matches[j].Class {
			return res.Matches[i].Class < res.Matches[j].Class
		}
		return res.Matches[i].Column < res.Matches[j].Column
	})
	return res
}

// ── name detectors ───────────────────────────────────────────────────────────────────────────────

type nameDetector struct {
	class Class
	// any of these substrings in the (lowercased) column name is a hint.
	needles []string
}

func (n nameDetector) matches(lname string) bool {
	for _, s := range n.needles {
		if strings.Contains(lname, s) {
			return true
		}
	}
	return false
}

var nameDetectors = []nameDetector{
	{ClassPII, []string{"ssn", "social_security", "socialsecurity", "national_id", "passport", "dob", "date_of_birth", "birth_date", "email", "phone", "mobile", "address", "first_name", "last_name", "full_name", "drivers_license", "tax_id"}},
	{ClassPHI, []string{"diagnosis", "icd", "mrn", "medical_record", "health", "patient", "prescription", "insurance_id", "npi"}},
	{ClassPCI, []string{"card_number", "cardnumber", "ccnum", "cc_number", "pan", "cvv", "cvc", "card_exp", "cardholder"}},
	{ClassSecret, []string{"api_key", "apikey", "secret", "private_key", "access_key", "client_secret"}},
	{ClassAuth, []string{"password", "passwd", "pwd", "password_hash", "session_token", "auth_token", "refresh_token"}},
}

// ── value detectors (structure-checked) ──────────────────────────────────────────────────────────

type valueDetector struct {
	class Class
	label string
	// test returns whether ONE value is a real instance of the class — regex shape AND a structural
	// check where one exists.
	test func(v string) bool
}

// count reports how many of the sampled values are real instances, and how many were sampled (non-empty).
func (d valueDetector) count(values []string) (hits, sampled int) {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		sampled++
		if d.test(v) {
			hits++
		}
	}
	return hits, sampled
}

var (
	emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	// A US SSN shape; the range check below rejects the reserved/invalid blocks a bare regex would pass.
	ssnRe    = regexp.MustCompile(`^(\d{3})-?(\d{2})-?(\d{4})$`)
	digitsRe = regexp.MustCompile(`^\d[\d \-]{11,21}\d$`)
	jwtRe    = regexp.MustCompile(`^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$`)
	awsKeyRe = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)
	pemRe    = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	bcryptRe = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)
)

var valueDetectors = []valueDetector{
	{ClassPII, "an email address", func(v string) bool { return emailRe.MatchString(v) }},
	{ClassPII, "a valid US SSN (range-checked)", validSSN},
	{ClassPCI, "a card number (Luhn-valid)", validCard},
	{ClassSecret, "an AWS access key", func(v string) bool { return awsKeyRe.MatchString(v) }},
	{ClassSecret, "a private key (PEM)", func(v string) bool { return pemRe.MatchString(v) }},
	{ClassSecret, "a JWT", func(v string) bool { return jwtRe.MatchString(v) }},
	{ClassAuth, "a bcrypt hash", func(v string) bool { return bcryptRe.MatchString(v) }},
}

// validSSN checks the shape AND rejects the ranges the SSA never issues, so a random nine-digit id is
// not miscalled an SSN.
func validSSN(v string) bool {
	m := ssnRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	area, group, serial := m[1], m[2], m[3]
	// Reserved / never-issued: area 000, 666, 900-999; group 00; serial 0000.
	if area == "000" || area == "666" || area >= "900" {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// validCard checks the shape AND the Luhn checksum, so a 16-digit order number is not miscalled a PAN.
func validCard(v string) bool {
	if !digitsRe.MatchString(v) {
		return false
	}
	var digits []int
	for _, r := range v {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhn(digits)
}

func luhn(digits []int) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return itoa(n) + " " + noun + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
