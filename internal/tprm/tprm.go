// Package tprm is THIRD-PARTY / VENDOR RISK MANAGEMENT — the one headline "finding issues" capability the
// compliance leaders (Vanta TPRM) have that the engine lacked. An SMB's security + compliance posture is only
// as strong as its vendors / subprocessors: a vendor with sensitive-data access and no SOC 2, a subprocessor
// with no DPA, a vendor with a known breach, or a critical vendor that was never reviewed are all real risks an
// "in-depth analysis of the assets" must surface — the vendor portfolio IS an asset class.
//
// Assess turns a vendor inventory snapshot into grounded vendor-risk findings, each mapped to the
// vendor-management controls (SOC 2 CC9.2, GDPR Art. 28 processors, PCI-DSS 12.8, ISO 27001 A.5.19/A.5.20
// supplier relationships, NIST SR/SA). Snapshot-driven, LLM-free, grounded (§10): it acts only on a vendor's
// own recorded attributes, and a well-managed vendor portfolio yields ZERO findings. Mirrors the SSPM / OSINT /
// clouddrift assessors; the live driver (POST /v1/tprm/ingest) lands findings in the same store, so vendor risk
// flows through issues / incidents / grc / hitl like any finding.
package tprm

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// DataAccess and Vendor are ALIASES of the stored register types in pkg/platform, not copies. The
// register is a store entity (internal/store may not import an internal package), and a mirrored
// struct here would be two types free to drift apart — with the drift landing in an audit artifact.
type DataAccess = platform.VendorDataAccess

const (
	DataNone      = platform.VendorDataNone
	DataMetadata  = platform.VendorDataMetadata
	DataPII       = platform.VendorDataPII
	DataSensitive = platform.VendorDataSensitive
)

// handlesPersonalData is a function rather than a method: DataAccess is an alias of a type in
// another package, and Go does not allow methods on those.
func handlesPersonalData(d DataAccess) bool { return d == DataPII || d == DataSensitive }

// Vendor is one third party in the inventory — its security/compliance attributes as recorded by the team
// or pulled from a TPRM connector. Every field is a stated fact, never inferred.
type Vendor = platform.Vendor

func hasCert(v Vendor, names ...string) bool {
	for _, c := range v.Certifications {
		for _, want := range names {
			if strings.EqualFold(strings.TrimSpace(c), want) {
				return true
			}
		}
	}
	return false
}

// Options tunes the assessment.
type Options struct {
	Now func() time.Time
	// ReviewDays is the max age before a critical/high vendor counts as stale-review (default 365).
	ReviewDays int
	NewID      func() string
}

// Assess turns the vendor inventory into grounded vendor-risk findings. A well-managed portfolio (every
// data-handling vendor certified, subprocessors with DPAs, no breaches, recent reviews) yields nil.
func Assess(vendors []Vendor, opts Options) []types.Finding {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	reviewDays := opts.ReviewDays
	if reviewDays <= 0 {
		reviewDays = 365
	}
	n := 0
	id := func() string {
		n++
		if opts.NewID != nil {
			return opts.NewID()
		}
		return fmt.Sprintf("tprm-%d", n)
	}

	var out []types.Finding
	for _, v := range vendors {
		name := strings.TrimSpace(v.Name)
		if name == "" {
			continue
		}

		// 1. A vendor that touches personal/sensitive data with NO SOC 2 or ISO 27001 attestation — the core
		// vendor-management gap (you can't rely on an unattested vendor with your data).
		if handlesPersonalData(v.DataAccess) && !hasCert(v, "SOC2", "SOC 2", "ISO27001", "ISO 27001") {
			out = append(out, finding(id(), "tprm::vendor-uncertified", types.SeverityHigh,
				"Vendor with data access has no SOC 2 / ISO 27001: "+name, name,
				fmt.Sprintf("%s can access %s data but holds no SOC 2 or ISO 27001 attestation — you have no independent assurance of its controls. Request its attestation report or replace it.", name, v.DataAccess),
				now, comp(types.Compliance{SOC2: []string{"CC9.2"}, ISO27001: []string{"A.5.19", "A.5.20"}, GDPR: []string{"Art. 28"}, NIST80053: []string{"SR-3", "SR-6"}, CISv8: []string{"15.1", "15.4"}})))
		}

		// 2. A subprocessor (processes our customers' data) with no DPA — a direct GDPR Art. 28 violation.
		if v.Subprocessor && !v.HasDPA {
			out = append(out, finding(id(), "tprm::subprocessor-no-dpa", types.SeverityHigh,
				"Subprocessor without a data-processing agreement: "+name, name,
				fmt.Sprintf("%s processes your customers' personal data as a subprocessor but no data-processing agreement (DPA) is on record — GDPR Art. 28 requires one. Execute a DPA before continued use.", name),
				now, comp(types.Compliance{SOC2: []string{"CC9.2"}, GDPR: []string{"Art. 28"}, ISO27701: []string{"7.2.6"}, NIST80053: []string{"SR-3"}})))
		}

		// 3. A vendor with a recorded breach AND access to our data — elevated, ongoing exposure.
		if v.Breached && v.DataAccess != DataNone && v.DataAccess != "" {
			out = append(out, finding(id(), "tprm::vendor-breach-history", types.SeverityHigh,
				"Vendor with a known breach has data access: "+name, name,
				fmt.Sprintf("%s has a security breach on record (%s) and can access %s data — reassess the relationship, confirm remediation, and review what of yours was exposed.", name, nz(v.BreachNote, "recorded"), nz(string(v.DataAccess), "your")),
				now, comp(types.Compliance{SOC2: []string{"CC9.2"}, GDPR: []string{"Art. 28", "Art. 32"}, NIST80053: []string{"SR-6", "IR-6"}, CISv8: []string{"15.7"}})))
		}

		// 4. A payments/card-handling vendor without PCI DSS — a PCI 12.8 service-provider gap.
		if v.HandlesCardData && !hasCert(v, "PCI", "PCI-DSS", "PCI DSS") {
			out = append(out, finding(id(), "tprm::card-vendor-no-pci", types.SeverityHigh,
				"Card-data vendor without PCI DSS: "+name, name,
				fmt.Sprintf("%s handles cardholder data but holds no PCI DSS attestation — PCI 12.8 requires you to manage service providers' PCI compliance. Obtain its Attestation of Compliance.", name),
				now, comp(types.Compliance{PCI: []string{"12.8.1", "12.8.4"}, SOC2: []string{"CC9.2"}, NIST80053: []string{"SR-3"}})))
		}

		// 5. A critical/high-criticality vendor not reviewed within the review window (or never) — the periodic
		// vendor-review obligation (SOC 2 CC9.2). Lower-criticality vendors don't trip this (grounded prioritization).
		if isHighCriticality(v.Criticality) && staleReview(v.LastAssessed, now, reviewDays) {
			out = append(out, finding(id(), "tprm::vendor-stale-review", types.SeverityMedium,
				"Critical vendor overdue for review: "+name, name,
				fmt.Sprintf("%s is a %s-criticality vendor that has not been reviewed in over %d days (%s) — schedule a periodic vendor risk review.", name, strings.ToLower(v.Criticality), reviewDays, nz(v.LastAssessed, "never assessed")),
				now, comp(types.Compliance{SOC2: []string{"CC9.2"}, ISO27001: []string{"A.5.22"}, NIST80053: []string{"SR-6"}, CISv8: []string{"15.3"}})))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func isHighCriticality(c string) bool {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "critical", "high":
		return true
	}
	return false
}

// staleReview reports whether a last-assessed date is missing or older than reviewDays. An unparseable
// date is treated as stale (a date we can't read can't prove a recent review).
func staleReview(last string, now time.Time, reviewDays int) bool {
	last = strings.TrimSpace(last)
	if last == "" {
		return true // never assessed
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, last); err == nil {
			return now.Sub(t.UTC()) > time.Duration(reviewDays)*24*time.Hour
		}
	}
	return true
}

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, c *types.Compliance) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "tprm", Severity: sev,
		Title: title, Endpoint: "vendor:" + endpoint, Description: desc,
		DiscoveredAt: now, VerificationStatus: types.VerificationVerified, Compliance: c,
	}
}

func comp(c types.Compliance) *types.Compliance { return &c }

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}
