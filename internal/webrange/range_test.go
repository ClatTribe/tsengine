package webrange

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// noRedirect client so we can observe 3xx Location headers.
func newClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// probeFor returns the canonical payload + a body/response predicate that is TRUE
// iff the response shows the class's deterministic indicator shape. This is an
// INDEPENDENT check of the environment — it does not call the agent or its
// internal indicators(), so a passing self-test validates the range itself.
func indicatorShown(class string, c *http.Client, base, path, param string) bool {
	send := func(payload string) (*http.Response, string) {
		u := base + path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := c.Get(u)
		if err != nil {
			return nil, ""
		}
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		return resp, string(buf[:n])
	}
	switch class {
	case ClassSQLi:
		r, body := send("'")
		return r != nil && r.StatusCode == 500 && regexp.MustCompile(`(?i)(SQL syntax|syntax error|SQLITE_ERROR|ORA-\d)`).MatchString(body)
	case ClassXSS:
		p := "\"><img src=x onerror=alert(1)>"
		_, body := send(p)
		return strings.Contains(body, p)
	case ClassRedirect:
		r, _ := send("https://attacker.example/")
		return r != nil && r.StatusCode >= 300 && r.StatusCode < 400 && strings.Contains(r.Header.Get("Location"), "attacker.example")
	case ClassPathTrav:
		_, body := send("../../../../etc/passwd")
		return strings.Contains(body, "root:")
	case ClassCmdi:
		_, body := send("127.0.0.1;id")
		return strings.Contains(body, "uid=")
	}
	return false
}

// TestRange_SelfConsistent independently verifies the environment: every
// exploitable target SHOWS its indicator, every decoy does NOT. If this fails the
// fixture is wrong (not the agent).
func TestRange_SelfConsistent(t *testing.T) {
	for _, seed := range []int64{1, 2, 3, 7, 42} {
		rg := Generate(seed, Opts{N: 14})
		srv := httptest.NewServer(rg.Handler())
		c := newClient()
		for _, tg := range rg.Manifest.Targets {
			shown := indicatorShown(tg.Class, c, srv.URL, tg.Path, tg.Param)
			if tg.Exploitable && !shown {
				t.Errorf("seed %d: exploitable %s (%s %s) did NOT show its indicator", seed, tg.ID, tg.Class, tg.Path)
			}
			if !tg.Exploitable && shown {
				t.Errorf("seed %d: DECOY %s (%s %s) leaked an indicator — fixture bug", seed, tg.ID, tg.Class, tg.Path)
			}
		}
		srv.Close()
	}
}

// TestRange_AgentSweep is the headline end-to-end test: the web agent (driven by
// the deterministic blind Prober) sweeps a freshly-generated range and must find
// EVERY real vuln while recording ZERO decoys — across several seeds. Zero decoys
// is the anti-circularity result: the prober attacks decoys identically, but the
// grounding gate refuses to record them.
func TestRange_AgentSweep(t *testing.T) {
	seeds := []int64{1, 2, 3, 7, 11, 42, 99}
	var totReal, totFound, totDecoyFlag, totInvented int
	for _, seed := range seeds {
		rg := Generate(seed, Opts{N: 14})
		srv := httptest.NewServer(rg.Handler())
		rep, sc, err := RunAgainst(context.Background(), nil, rg, srv.URL, 0)
		srv.Close()
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		t.Logf("seed=%d exploitable=%d decoys=%d → recall=%.0f%% decoys_flagged=%d invented=%d verified_findings=%d",
			seed, rg.Manifest.Exploitable, rg.Manifest.Decoys, sc.Recall*100, sc.DecoyFlagged, sc.Invented, countVerified(rep))
		if !sc.Pass {
			t.Errorf("seed %d FAIL:\n%s", seed, Render(sc))
		}
		// grounded findings must all be Verified (re-fire reproduced the indicator)
		for _, f := range rep.Findings {
			if !f.Verified {
				t.Errorf("seed %d: finding %s (%s) not Verified", seed, f.ID, f.Class)
			}
		}
		totReal += sc.RealTotal
		totFound += sc.RealFound
		totDecoyFlag += sc.DecoyFlagged
		totInvented += sc.Invented
	}
	t.Logf("AGGREGATE over %d seeds: recall=%.1f%% (%d/%d)  decoys_flagged=%d  invented=%d",
		len(seeds), 100*float64(totFound)/float64(totReal), totFound, totReal, totDecoyFlag, totInvented)
	if totFound != totReal {
		t.Errorf("aggregate recall < 100%%: %d/%d", totFound, totReal)
	}
	if totDecoyFlag != 0 || totInvented != 0 {
		t.Errorf("grounding leaked: decoys_flagged=%d invented=%d (must be 0)", totDecoyFlag, totInvented)
	}
}

// TestRange_DecoysArePresent guards the test's own validity: a range with the
// default decoy fraction must actually contain decoys (else "0 decoys flagged"
// proves nothing).
func TestRange_DecoysArePresent(t *testing.T) {
	rg := Generate(7, Opts{N: 14})
	if rg.Manifest.Decoys == 0 {
		t.Fatal("range has no decoys — the anti-circularity test would be vacuous")
	}
	if rg.Manifest.Exploitable == 0 {
		t.Fatal("range has no exploitable targets")
	}
	// at least one WAF'd exploitable somewhere across a few seeds (bypass exercised)
	waf := false
	for _, s := range []int64{1, 2, 3, 7, 11, 42, 99} {
		for _, tg := range Generate(s, Opts{N: 14}).Manifest.Targets {
			if tg.WAF {
				waf = true
			}
		}
	}
	if !waf {
		t.Error("no WAF'd target across seeds — bypass path never exercised")
	}
}

// TestRange_NoSUTLeakInScorer is the anti-overfit guard (CLAUDE.md §14.2): the
// scorer must not branch on any environment-specific identifier.
func TestRange_NoSUTLeakInScorer(t *testing.T) {
	data, err := os.ReadFile("score.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"attacker.example", "/etc/passwd", "evil.test", "/product", "/greet", "onerror"} {
		if strings.Contains(string(data), banned) {
			t.Errorf("score.go references SUT-specific token %q — scoring must be fixture-agnostic", banned)
		}
	}
}

func countVerified(rep *webagent.Report) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Verified {
			n++
		}
	}
	return n
}
