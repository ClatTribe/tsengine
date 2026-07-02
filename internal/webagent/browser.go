package webagent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// browser.go is the headless-browser render tool (host-side chromedp). Reflected input in HTML SOURCE
// is not XSS; only a real browser executing the DOM proves it. browser_render loads a URL in headless
// Chrome, runs its JavaScript, and reports the DETERMINISTIC execution signals:
//   - a JS dialog opening (alert/prompt/confirm) — the canonical BENIGN proof that a script executed
//     (js_executed → grounds a class=dom_xss / stored_xss finding);
//   - console output;
//   - any callback the page made to the OOB collector (a blind/stored-XSS cookie beacon → exfil).
// Host-side + host-allowlist-scoped (the same guard send_request uses). No sandbox rebuild (§12.6).

// renderResult is what one render observed.
type renderResult struct {
	DialogFired bool
	DialogText  string
	Console     []string
	DOM         string
	Elapsed     time.Duration
}

// browserAllocOpts are the exec-allocator flags: the chromedp defaults (headless) plus the ones that
// make Chrome run reliably headless on a server / in Docker (no-sandbox, no /dev/shm reliance).
func browserAllocOpts() []chromedp.ExecAllocatorOption {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	return append(opts,
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
}

// renderPage loads rawURL in headless Chrome, lets scripts run for `settle`, and returns what it saw.
// Errors if no Chrome/Chromium is available (or TSENGINE_BROWSER_DISABLED=1) — the caller degrades.
func renderPage(parent context.Context, rawURL string, settle time.Duration) (renderResult, error) {
	if os.Getenv("TSENGINE_BROWSER_DISABLED") == "1" {
		return renderResult{}, fmt.Errorf("browser disabled (TSENGINE_BROWSER_DISABLED=1)")
	}
	if parent == nil {
		parent = context.Background()
	}
	if settle <= 0 {
		settle = 1500 * time.Millisecond
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, browserAllocOpts()...)
	defer cancelAlloc()
	bctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	tctx, cancelT := context.WithTimeout(bctx, 25*time.Second)
	defer cancelT()

	var mu sync.Mutex
	var res renderResult
	chromedp.ListenTarget(tctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			mu.Lock()
			res.DialogFired = true
			res.DialogText = e.Message
			mu.Unlock()
			// a JS dialog BLOCKS the page until handled — accept it from a separate goroutine so the
			// render can proceed (and so a payload's alert() is not left hanging).
			go func() { _ = chromedp.Run(tctx, page.HandleJavaScriptDialog(true)) }()
		case *runtime.EventConsoleAPICalled:
			var parts []string
			for _, a := range e.Args {
				if len(a.Value) > 0 {
					parts = append(parts, strings.Trim(string(a.Value), `"`))
				}
			}
			if len(parts) > 0 {
				mu.Lock()
				res.Console = append(res.Console, strings.Join(parts, " "))
				mu.Unlock()
			}
		}
	})

	var dom string
	start := time.Now()
	err := chromedp.Run(tctx,
		chromedp.Navigate(rawURL),
		chromedp.Sleep(settle),
		chromedp.OuterHTML("html", &dom, chromedp.ByQuery),
	)
	res.Elapsed = time.Since(start)
	mu.Lock()
	res.DOM = dom
	fired := res.DialogFired
	mu.Unlock()
	// a dialog can interrupt Run with an error even though the render "succeeded" for our purpose.
	if err != nil && !fired {
		return res, err
	}
	return res, nil
}

// tBrowserRender is the tool: render a URL, record the observation as a Turn (evidence), and surface
// the execution signals.
func tBrowserRender(cc *Context, args map[string]any) string {
	rawURL := strings.TrimSpace(argStr(args, "url"))
	if rawURL == "" {
		return "ERROR: url is required (the page to render — a reflected-XSS URL, or the page that displays a stored payload)"
	}
	// Same scope guard as send_request: only render an allowlisted host (runs BEFORE launching Chrome).
	if cc.req != nil && !cc.req.AllowedURL(rawURL) {
		return "OUT OF SCOPE: " + rawURL + " is not in the authorized target allowlist — render blocked"
	}
	res, err := renderPage(cc.ctx, rawURL, 0)
	if err != nil {
		return "BROWSER FAILED: " + err.Error() + " — a Chrome/Chromium binary must be available on the host (or set TSENGINE_BROWSER_DISABLED=1 to skip browser rendering)."
	}
	cc.turnN++
	var ind []string
	if res.DialogFired {
		ind = append(ind, "js_executed") // a JS dialog opened → the script EXECUTED in a real DOM
	}
	dom := res.DOM
	if len(dom) > evidenceBodyCap {
		dom = dom[:evidenceBodyCap] + "…"
	}
	cc.History = append(cc.History, Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "GET(browser)", URL: rawURL,
		Status: 200, Indicators: ind, Elapsed: res.Elapsed.String(), RespSnippet: dom,
	})

	var b strings.Builder
	fmt.Fprintf(&b, "t-%03d  rendered %s in headless Chrome (%s)\n", cc.turnN, rawURL, res.Elapsed.Round(time.Millisecond))
	if res.DialogFired {
		fmt.Fprintf(&b, "  js_executed: a JavaScript DIALOG fired (message: %q) — your script EXECUTED in the DOM. This is real DOM XSS; record it as class=dom_xss citing t-%03d.\n", capLine(res.DialogText, 200), cc.turnN)
	} else {
		b.WriteString("  no JS dialog fired — the payload did not execute (it may be encoded/sanitized in the DOM, or needs a different injection context).\n")
	}
	if len(res.Console) > 0 {
		c := res.Console
		if len(c) > 5 {
			c = c[:5]
		}
		fmt.Fprintf(&b, "  console: %s\n", capLine(strings.Join(c, " | "), 300))
	}
	// a blind/stored-XSS beacon may have hit the OOB collector during the render
	if cc.oob != nil {
		if hits := cc.oob.Hits(""); len(hits) > 0 {
			fmt.Fprintf(&b, "  NOTE: %d OOB callback(s) recorded during render — run oob_check for the exfil'd data (document.cookie / a flag).\n", len(hits))
		}
	}
	if snip := strings.TrimSpace(res.DOM); snip != "" {
		if len(snip) > llmSnippetCap {
			snip = snip[:llmSnippetCap] + "…"
		}
		fmt.Fprintf(&b, "<<RENDERED DOM (untrusted)>> %s <<END>>", strings.ReplaceAll(snip, "\n", " "))
	}
	return b.String()
}
