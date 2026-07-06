package webagent

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Race-condition / TOCTOU grounding — the FP-free proof for a limit-bypass race (redeem a coupon
// twice, withdraw past a balance, bypass a one-time action): firing the same limited operation
// CONCURRENTLY succeeds MORE times than firing it SERIALLY, because the app checks-then-uses without a
// lock. Grounded by a serial-vs-concurrent success differential on equivalent (reset) state — an
// observed count, no policy input, so a no-limit endpoint (all succeed both ways) and a properly-locked
// one (both respect the limit) do NOT fire. The LLM proposes the request + a success marker + a reset;
// the deterministic predicate disposes (same house pattern as bola_probe/tamper_probe). NOTE: this is
// the limit-bypass race class; a session-swap AuthZ TOCTOU (e.g. XBEN-088) is a different sub-type this
// does not cover.

// raceConfirmed: concurrency produced strictly MORE successes than a serial run of the same operation
// (which respected the limit) — the TOCTOU signal. Equal counts (no limit, or a proper lock) do not fire.
func raceConfirmed(serialWins, concWins int) bool {
	return concWins > serialWins && serialWins >= 1
}

// tRaceProbe fires the operation N times SERIALLY (counting successes), resets, then N times
// CONCURRENTLY, and sets `race_confirmed` when the concurrent run beat the serial one. Each fire uses a
// fresh Requester carrying the agent's current session cookie (so concurrent goroutines never share a
// jar), keeping the authenticated context without a data race.
func tRaceProbe(cc *Context, args map[string]any) string {
	method := strings.ToUpper(argStr(args, "method"))
	if method == "" {
		method = "POST"
	}
	url := argStr(args, "url")
	marker := strings.TrimSpace(argStr(args, "success_marker"))
	body := argStr(args, "body")
	if url == "" || marker == "" {
		return "ERROR: race_probe(method, url, success_marker, [body, n, reset_method, reset_url, reset_body]) — url + success_marker required. " +
			"success_marker = a string that appears ONLY when the limited operation SUCCEEDS (e.g. 'coupon redeemed', 'transfer complete'). " +
			"reset_url = a request that restores the state between the serial and concurrent phases (re-arm the coupon, reset the balance) so the two phases run on equivalent state."
	}
	if !cc.req.AllowedURL(url) {
		return "ERROR: url is out of scope."
	}
	n := argInt(args, "n")
	if n <= 1 {
		n = 5
	}
	if n > 20 {
		n = 20
	}
	hosts := cc.req.AllowHosts()
	cookie := cc.req.CookieHeader(url) // carry the agent's authenticated session into every fire
	hdr := func() map[string]string {
		h := map[string]string{}
		if method != "GET" {
			h["Content-Type"] = "application/x-www-form-urlencoded"
		}
		if cookie != "" {
			h["Cookie"] = cookie
		}
		if len(h) == 0 {
			return nil
		}
		return h
	}
	fire := func() bool {
		r := NewRequester(hosts, 3, 0)
		resp, err := r.Send(cc.ctx, method, url, body, hdr())
		return err == nil && strings.Contains(resp.Body, marker)
	}
	reset := func() {
		ru := argStr(args, "reset_url")
		if ru == "" || !cc.req.AllowedURL(ru) {
			return
		}
		rm := strings.ToUpper(argStr(args, "reset_method"))
		if rm == "" {
			rm = "POST"
		}
		r := NewRequester(hosts, 3, 0)
		_, _ = r.Send(cc.ctx, rm, ru, argStr(args, "reset_body"), hdr())
	}

	// Serial phase — respects the limit.
	reset()
	serialWins := 0
	for i := 0; i < n; i++ {
		if fire() {
			serialWins++
		}
	}
	// Concurrent phase — the TOCTOU window lets several through.
	reset()
	var concWins int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fire() {
				atomic.AddInt64(&concWins, 1)
			}
		}()
	}
	wg.Wait()

	confirmed := raceConfirmed(serialWins, int(concWins))
	cc.turnN++
	ind := []string{}
	if confirmed {
		ind = append(ind, "race_confirmed")
	}
	t := Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: method, URL: url, Indicators: ind,
		RespSnippet: fmt.Sprintf("race differential (n=%d): serial_successes=%d concurrent_successes=%d", n, serialWins, concWins),
	}
	cc.History = append(cc.History, t)

	if !confirmed {
		return fmt.Sprintf("%s: race_confirmed NOT set — serial=%d concurrent=%d (n=%d).\n"+
			"Need concurrent > serial AND serial >= 1: the serial run must RESPECT a limit (few successes) while the "+
			"concurrent run BREAKS it (more). If serial==concurrent==n the endpoint has no limit; if both are low it's "+
			"properly locked. Ensure success_marker matches ONLY a successful operation and reset_url restores state between phases.",
			t.ID, serialWins, concWins, n)
	}
	return fmt.Sprintf("%s: race_confirmed — the operation succeeded %d times CONCURRENTLY but only %d times SERIALLY (n=%d): "+
		"a check-then-use TOCTOU / limit-bypass race. Cite %s in record_finding(class=race_condition).",
		t.ID, concWins, serialWins, n, t.ID)
}
