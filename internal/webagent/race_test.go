package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRaceConfirmed_Predicate: a limit-bypass / TOCTOU race is grounded by a serial-vs-concurrent
// success differential — firing the same limited operation CONCURRENTLY yields MORE successes than
// firing it SERIALLY (which respects the limit). A no-limit endpoint (all succeed both ways) and a
// properly-locked limit (both respect it) do NOT fire — FP-free.
func TestRaceConfirmed_Predicate(t *testing.T) {
	cases := []struct {
		name                 string
		serialWins, concWins int
		want                 bool
	}{
		{"toctou limit bypass", 1, 4, true},
		{"no limit (all succeed both ways)", 5, 5, false},
		{"properly locked limit", 1, 1, false},
		{"concurrent fewer (noise)", 3, 2, false},
		{"op never succeeds", 0, 0, false},
	}
	for _, c := range cases {
		if got := raceConfirmed(c.serialWins, c.concWins); got != c.want {
			t.Errorf("%s: raceConfirmed(%d,%d)=%v want %v", c.name, c.serialWins, c.concWins, got, c.want)
		}
	}
}

// TestRaceProbe_EndToEnd: a coupon endpoint with a TOCTOU (read count, wide window, then write) lets
// concurrent requests redeem past the limit-of-1, while serial requests respect it. race_probe fires
// serial then concurrent (with a reset between) and confirms; a properly-locked endpoint does not.
func TestRaceProbe_EndToEnd(t *testing.T) {
	newServer := func(locked bool) *httptest.Server {
		var mu sync.Mutex
		applied := 0
		var lock sync.Mutex // the "proper" lock (used only when locked)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/reset" {
				mu.Lock()
				applied = 0
				mu.Unlock()
				fmt.Fprint(w, "reset")
				return
			}
			// /redeem — limit 1, but with a check-then-use window (TOCTOU) unless properly locked.
			if locked {
				lock.Lock()
				defer lock.Unlock()
			}
			mu.Lock()
			cur := applied
			mu.Unlock()
			time.Sleep(25 * time.Millisecond) // the TOCTOU window
			if cur < 1 {
				mu.Lock()
				applied++
				mu.Unlock()
				fmt.Fprint(w, "coupon redeemed")
				return
			}
			fmt.Fprint(w, "already used")
		}))
	}

	// Vulnerable (TOCTOU) — must confirm.
	vuln := newServer(false)
	defer vuln.Close()
	cc := &Context{Target: vuln.URL, ctx: context.Background()}
	cc.req = NewRequester([]string{hostOf(vuln.URL)}, 200, 0)
	tRaceProbe(cc, map[string]any{
		"method": "POST", "url": vuln.URL + "/redeem", "success_marker": "coupon redeemed", "n": 6,
		"reset_method": "POST", "reset_url": vuln.URL + "/reset",
	})
	if len(cc.History) == 0 || !hasIndicator(cc.History[len(cc.History)-1], "race_confirmed") {
		t.Fatalf("TOCTOU coupon race did not fire race_confirmed: %+v", cc.History)
	}
	tid := cc.History[len(cc.History)-1].ID
	if rec := tRecord(cc, map[string]any{"route": "/redeem", "class": "race_condition", "evidence": []any{tid}}); strings.Contains(rec, "REJECTED") {
		t.Fatalf("race_condition rejected despite race_confirmed: %s", rec)
	}

	// Properly locked — must NOT confirm.
	locked := newServer(true)
	defer locked.Close()
	cc2 := &Context{Target: locked.URL, ctx: context.Background()}
	cc2.req = NewRequester([]string{hostOf(locked.URL)}, 200, 0)
	tRaceProbe(cc2, map[string]any{
		"method": "POST", "url": locked.URL + "/redeem", "success_marker": "coupon redeemed", "n": 6,
		"reset_method": "POST", "reset_url": locked.URL + "/reset",
	})
	if hasIndicator(cc2.History[len(cc2.History)-1], "race_confirmed") {
		t.Fatalf("properly-locked endpoint falsely confirmed a race: %+v", cc2.History)
	}
}
