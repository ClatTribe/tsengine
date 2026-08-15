package operate

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// errResolver fails every lookup with a supplied error, so the two cases — "DNS said there is no
// such record" and "DNS said nothing" — can be told apart deterministically without real network.
type errResolver struct{ err error }

func (r errResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, r.err }

func notFound() error { return &net.DNSError{Err: "no such host", IsNotFound: true} }
func timedOut() error { return &net.DNSError{Err: "i/o timeout", IsTimeout: true} }
func servFail() error { return errors.New("SERVFAIL") }

// TestLookupTimeoutIsUnknownNotAbsent is the regression guard for a §10 grounding violation that
// could reach a paying customer's posture page: FetchDomain's `if err == nil` swallowed a DNS
// TIMEOUT exactly like a definitive "no such record", so DMARC stayed "" and downstream reported
// "DMARC not enforced — attackers can spoof your domain" about a domain we never actually read.
func TestLookupTimeoutIsUnknownNotAbsent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for name, err := range map[string]error{"timeout": timedOut(), "servfail": servFail()} {
		t.Run(name, func(t *testing.T) {
			e := &EmailAuth{Resolver: errResolver{err: err}, DKIMSelectors: []string{"google"}}
			dc := e.FetchDomain(ctx, "acme.com")

			for _, f := range []string{"dmarc", "spf", "dkim"} {
				if !dc.Unknown(f) {
					t.Errorf("%s: %s should be UNKNOWN when the lookup could not be answered (Unresolved=%v)", name, f, dc.Unresolved)
				}
			}
			// And the checks must stay silent rather than assert a gap we never observed.
			ws := Workspace{Org: "acme", Domains: []DomainConfig{dc}}
			for _, f := range Assess(ws, Options{}) {
				if strings.Contains(f.RuleID, "dmarc") || strings.Contains(f.RuleID, "spf-dkim") {
					t.Errorf("%s: fired %q on an unanswered lookup — that is a fabricated finding", name, f.RuleID)
				}
			}
		})
	}
}

// TestNoSuchRecordIsStillAFinding is the other half, and the more important one: this fix must not
// silence real findings. A definitive negative answer means the record genuinely is not published,
// which is exactly the thing we are supposed to report.
func TestNoSuchRecordIsStillAFinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	e := &EmailAuth{Resolver: errResolver{err: notFound()}, DKIMSelectors: []string{"google"}}
	dc := e.FetchDomain(ctx, "acme.com")

	if len(dc.Unresolved) != 0 {
		t.Fatalf("NXDOMAIN must be a finding, not UNKNOWN — got Unresolved=%v", dc.Unresolved)
	}
	var got []string
	for _, f := range Assess(Workspace{Org: "acme", Domains: []DomainConfig{dc}}, Options{}) {
		got = append(got, f.RuleID)
	}
	var sawDMARC bool
	for _, r := range got {
		if strings.Contains(r, "dmarc-not-enforced") {
			sawDMARC = true
		}
	}
	if !sawDMARC {
		t.Errorf("a domain that genuinely publishes no DMARC must still be reported; got %v", got)
	}
}

// TestSnapshotDomainsUnaffected — posted snapshots assert their values directly and never populate
// Unresolved, so this change must be invisible to them.
func TestSnapshotDomainsUnaffected(t *testing.T) {
	dc := DomainConfig{Name: "acme.com"} // no DMARC/SPF/DKIM, no Unresolved — a snapshot saying "absent"
	var got []string
	for _, f := range Assess(Workspace{Org: "acme", Domains: []DomainConfig{dc}}, Options{}) {
		got = append(got, f.RuleID)
	}
	if len(got) == 0 {
		t.Error("a snapshot asserting no email-auth must still produce findings")
	}
}
