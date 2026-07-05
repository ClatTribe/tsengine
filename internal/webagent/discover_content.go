package webagent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// discoverBudget caps the TOTAL wall-clock of one discover_content call. The probes run serially (the
// Requester isn't goroutine-safe — it has a request budget + rate limiter), each up to the Requester's
// 15s per-request timeout, so 45 paths could otherwise block the ReAct agent for ~11 minutes if the
// target holds connections or is slow (grounded: a live XBEN-103 run hung the whole agent for 7+ min
// here). A bounded context makes the WHOLE sweep return within ~budget with whatever it found so far —
// content discovery is best-effort, not exhaustive. A var so tests can shrink it.
var discoverBudget = 20 * time.Second

// discover_content.go closes a general recon gap: discoverSurface only sees LINKED pages and VISIBLE
// form params. Real targets hide the interesting surface — an unlinked admin/private page, a
// server-side-only query param (?file=, ?debug=) — so the agent never learns it exists and can't
// reach the vuln. This tool is a fast, bounded, host-side mini content/param bruteforcer (ffuf/arjun
// in miniature): it probes a SMALL curated wordlist of common hidden paths + common param names and
// reports a hit ONLY on a grounded DIFFERENTIAL vs a baseline (a 404 for paths, the no-param page for
// params) — so it never invents surface (§10). Wordlists are GENERIC pentest defaults (admin.php,
// file, page, id…), not tied to any target.

// commonPaths — the highest-signal unlinked endpoints/files across web apps. GENERIC pentest defaults
// (no target-specific names — §14.2); ordered by likelihood. Includes the dynamic AUTH + CRUD/query
// handlers where SQLi/IDOR actually live (login.php, search.php, product.php, …) — a static site's
// forms often point at a placeholder action while the real injectable endpoint is unlinked, so name
// discovery is the only way to reach it. Also the JSON-API / RPC ACTION-verb routes (run, exec, render,
// healthcheck, /api/*, graphql) — a modern Flask/FastAPI/Express service hides its functional surface
// behind action verbs, NOT .php file names, so a purely file-oriented list is blind to the whole
// JSON-API class (observed live: XBEN-082, a Flask microservice, probed 45 PHP paths → "nothing found"
// and the agent never reached the eval/render sink). Bounded (~60) to respect the request budget.
var commonPaths = []string{
	// exposure / config / meta
	"admin.php", "admin", "private.php", "private", "config.php", ".env", ".git/HEAD",
	"robots.txt", "backup.zip", "backup.sql", "phpinfo.php", "info.php", "test.php",
	"upload.php", "api.php", "dashboard.php", "panel.php", "server-status",
	// auth handlers (the login/register SQLi + auth-bypass sinks)
	"login.php", "login", "signin.php", "signin", "signup.php", "register.php", "auth.php",
	"authenticate.php", "checklogin.php", "logout.php",
	// CRUD / query handlers (SQLi/IDOR sinks behind a listing or detail view)
	"search.php", "product.php", "products.php", "item.php", "view.php", "details.php",
	"user.php", "users.php", "profile.php", "account.php", "news.php", "article.php",
	"category.php", "list.php", "index.php", "home.php", "api/login",
	// JSON-API / RPC ACTION-verb routes (SSRF/eval/render/cmd-exec sinks in Flask/FastAPI/Express/Spring
	// microservices — the surface a .php wordlist can't see). Generic service verbs, not target-specific.
	"api", "graphql", "graphiql", "healthcheck", "health", "status", "actuator", "debug", "console",
	"run", "exec", "execute", "eval", "render", "fetch", "proxy", "invoke",
	"api/run", "api/exec", "api/render", "api/fetch", "api/proxy", "api/health", "api/data",
}

// commonParams — the standard server-side query-param names (LFI/IDOR/injection/debug). GENERIC.
var commonParams = []string{
	"file", "page", "path", "include", "id", "cmd", "exec", "q",
	"search", "url", "debug", "admin", "action", "name", "user", "view",
}

// tDiscoverContent dispatches: params_for=<page> → param discovery on that page; else → path discovery
// under the target/base.
func tDiscoverContent(cc *Context, args map[string]any) string {
	if page := strings.TrimSpace(argStr(args, "params_for")); page != "" {
		return discoverParams(cc, page)
	}
	base := strings.TrimSpace(argStr(args, "url"))
	if base == "" {
		base = cc.Target
	}
	if base == "" {
		return "ERROR: no target — pass url=<base> to probe paths, or params_for=<page-url> to probe params"
	}
	return discoverPaths(cc, base)
}

// discoverPaths probes commonPaths under base, reporting those whose response differs from a random-path
// 404 baseline (a real page: 200/301/302/401/403/dir-listing). Found paths are added to cc.Routes.
func discoverPaths(cc *Context, base string) string {
	ctx, cancel := context.WithTimeout(cc.ctx, discoverBudget)
	defer cancel()
	base = strings.TrimRight(base, "/")
	baseResp, err := cc.req.Send(ctx, "GET", base+"/zz"+randHex(6), "", nil)
	if err != nil {
		return "REQUEST FAILED (baseline): " + err.Error()
	}
	// Baseline auto-calibration (ffuf/arjun): a SECOND bogus path. If two nonexistent paths already
	// differ in size beyond the threshold, the 404/catch-all body is non-deterministic (rotating
	// banner, path-derived "did you mean", variable-length nonce) — the size-diff signal would then fire
	// for EVERY probed path (a false-positive flood violating the "no invented surface" promise, §10).
	// When unstable, fall back to STATUS-ONLY matching, which stays grounded.
	base2, err2 := cc.req.Send(ctx, "GET", base+"/zz"+randHex(6), "", nil)
	sizeReliable := err2 == nil && base2.Status == baseResp.Status && !sizeDiffers(baseResp.Body, base2.Body)
	var found []string
	for _, p := range commonPaths {
		resp, err := cc.req.Send(ctx, "GET", base+"/"+p, "", nil)
		if err != nil { // budget exhausted / network — stop with what we have
			break
		}
		if pathDiffers(baseResp, resp, sizeReliable) {
			found = append(found, fmt.Sprintf("/%s (%d)", p, resp.Status))
			cc.Routes = appendUniq(cc.Routes, base+"/"+p)
		}
	}
	if len(found) == 0 {
		note := ""
		if !sizeReliable {
			note = " (the 404 page is dynamic — matched on status only, so size-only hidden pages may be missed; probe likely names manually)"
		}
		return fmt.Sprintf("no common hidden paths found (probed %d)%s — the surface may be fully linked, or uses non-standard names.", len(commonPaths), note)
	}
	return "DISCOVERED hidden paths (not linked — probe them): " + strings.Join(found, ", ")
}

// discoverParams probes commonParams on page, reporting those that CHANGE the response vs the no-param
// baseline (a reflected canary, a status change, or a meaningful size change) — the sign of a real
// server-side parameter. Reported as LEADS (the agent verifies).
func discoverParams(cc *Context, page string) string {
	ctx, cancel := context.WithTimeout(cc.ctx, discoverBudget)
	defer cancel()
	sep := "?"
	if strings.Contains(page, "?") {
		sep = "&"
	}
	canary := "zq" + randHex(5)
	// Baseline is a BOGUS param (a random name the app can't know), NOT the bare page. This is arjun's
	// trick: it distinguishes "the app reacts to THIS param" from "the app reacts/reflects for ANY
	// param", which kills the false positives a bare-page baseline produces — and lets us use a small
	// size threshold to catch params whose only effect is a short message (e.g. "File not found").
	base, err := cc.req.Send(ctx, "GET", page+sep+"zz"+randHex(6)+"="+canary, "", nil)
	if err != nil {
		return "REQUEST FAILED (baseline): " + err.Error()
	}
	// Same auto-calibration as discoverPaths: a SECOND bogus-param request. If the page body already
	// varies beyond the fine threshold between two identical-semantics requests, it's dynamic (nonce,
	// rotating content) — the size-diff signal would then flag EVERY inert param, so we suppress it and
	// keep only the grounded reflected-canary + status signals.
	base2, err2 := cc.req.Send(ctx, "GET", page+sep+"zz"+randHex(6)+"="+canary, "", nil)
	sizeReliable := err2 == nil && base2.Status == base.Status && !paramSizeDiffers(base.Body, base2.Body)
	var found []string
	for _, name := range commonParams {
		resp, err := cc.req.Send(ctx, "GET", page+sep+name+"="+canary, "", nil)
		if err != nil {
			break
		}
		why := ""
		switch {
		case strings.Contains(resp.Body, canary) && !strings.Contains(base.Body, canary):
			why = "reflected" // echoes this param's value specifically (not the bogus one)
		case resp.Status != base.Status:
			why = fmt.Sprintf("status %d→%d", base.Status, resp.Status)
		case sizeReliable && paramSizeDiffers(base.Body, resp.Body):
			why = "response changed"
		}
		if why != "" {
			found = append(found, name+" ("+why+")")
		}
	}
	if len(found) == 0 {
		return fmt.Sprintf("no common params altered %s (probed %d) — it may take a different param, or none.", page, len(commonParams))
	}
	return "PARAMS that change " + page + " (leads — try payloads on them): " + strings.Join(found, ", ")
}

// pathDiffers reports whether resp looks like a real page vs the 404 baseline. sizeReliable is false
// when the baseline is non-deterministic (calibration failed) — then only a status change counts, so a
// dynamic 404 can't manufacture a hit for every probe.
func pathDiffers(base, resp *Resp, sizeReliable bool) bool {
	if resp.Status != base.Status {
		return true
	}
	return sizeReliable && resp.Status < 400 && sizeDiffers(base.Body, resp.Body)
}

// sizeDiffers reports a meaningful body-length change for PATH discovery (coarser — a real page vs a
// 404 differs a lot; ignore small soft-404 noise).
func sizeDiffers(a, b string) bool {
	return absDiff(len(a), len(b)) > 48
}

// paramSizeDiffers is the finer PARAM threshold — safe because the bogus-param baseline already means
// an inert param renders byte-identically (delta 0), so a small non-zero delta is a real behavioural
// change (e.g. an added "File not found" message).
func paramSizeDiffers(a, b string) bool {
	return absDiff(len(a), len(b)) > 16
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
