package osint

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// a representative Cavalier search-by-domain response: two infections holding acme.com credentials.
const cavalierSample = `{
  "message": "ok",
  "data": {
    "total": 2,
    "stealers": [
      {"stealer_family":"RedLine","date_compromised":"2024-03-11T08:12:00Z","top_logins":["alice@acme.com"],"top_passwords":["hunter2"]},
      {"stealer_family":"Lumma","date_compromised":"2024-05-02T00:00:00Z","top_logins":["https://okta.acme.com/login"],"top_passwords":[]}
    ]
  }
}`

func TestParseHudsonRock(t *testing.T) {
	sls := ParseHudsonRock("acme.com", []byte(cavalierSample))
	if len(sls) != 2 {
		t.Fatalf("want 2 stealer logs, got %d", len(sls))
	}
	// sorted by email → alice@acme.com first
	a := sls[0]
	if a.Email != "alice@acme.com" || a.Malware != "RedLine" || a.Date != "2024-03-11" || !a.Password || a.Source != "hudsonrock" {
		t.Errorf("first stealer log wrong: %+v", a)
	}
	// the second record's login is a service URL containing the domain → grounded, email best-effort
	b := sls[1]
	if b.Malware != "Lumma" || b.Password {
		t.Errorf("second stealer log wrong (no plaintext pw): %+v", b)
	}
	if b.Domain != "acme.com" {
		t.Errorf("domain must be the queried org domain: %q", b.Domain)
	}
}

func TestParseHudsonRock_CleanAndMalformed(t *testing.T) {
	if sls := ParseHudsonRock("acme.com", []byte(`{"data":{"stealers":[]}}`)); sls != nil {
		t.Errorf("a clean org must yield no stealer logs, got %v", sls)
	}
	for _, b := range []string{"", "not json", "[]", "   "} {
		if sls := ParseHudsonRock("acme.com", []byte(b)); sls != nil {
			t.Errorf("input %q must yield no findings", b)
		}
	}
	if sls := ParseHudsonRock("", []byte(cavalierSample)); sls != nil {
		t.Error("empty domain must yield nothing")
	}
}

// TestCollectStealerLogs_Assessable: the collected snapshot flows through Assess into the highest-severity
// osint::stealer-log finding (a corporate credential with a plaintext password is critical).
func TestCollectStealerLogs_Assessable(t *testing.T) {
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "acme.com") {
			return []byte(cavalierSample), nil
		}
		return nil, errors.New("no data")
	}
	snap := CollectStealerLogs(context.Background(), "Acme", []string{"acme.com"}, fetch)
	if len(snap.StealerLogs) != 2 {
		t.Fatalf("want 2 stealer logs in the snapshot, got %d", len(snap.StealerLogs))
	}
	findings := Assess(snap, Options{})
	var stealerFindings int
	for _, f := range findings {
		if strings.Contains(f.RuleID, "stealer-log") {
			stealerFindings++
		}
	}
	if stealerFindings == 0 {
		t.Error("stealer logs must produce osint::stealer-log findings via Assess")
	}
}

// TestCollectStealerLogs_BestEffort: one domain's fetch failure never aborts the collection.
func TestCollectStealerLogs_BestEffort(t *testing.T) {
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "good.com") {
			return []byte(cavalierSample), nil
		}
		return nil, errors.New("boom")
	}
	snap := CollectStealerLogs(context.Background(), "Acme", []string{"bad.com", "good.com"}, fetch)
	if len(snap.StealerLogs) == 0 {
		t.Error("a failing domain must not abort collection of a working one")
	}
}
