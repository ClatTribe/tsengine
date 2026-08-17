package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// A COMPLETE, scored OFFENSE run over a multi-class neutral suite, driven by whatever
// LLM the env resolves — set LLM_BASE_URL to a relay/proxy for a frontier brain. Each
// scenario is a live, deliberately-(in)secure httptest target and a seed; the agent must
// PROVE the vuln (the deterministic indicator must fire, and record_finding is rejected
// otherwise) or, for the FP-control target, correctly find nothing to record.
//
// Distinct classes exercise different proving paths:
//
//	open_redirect  — a 302 to an external Location (external_redirect indicator)
//	sqli           — an emitted SQL error string on a quote (sql_error indicator)
//	xss (reflected)— the payload echoed verbatim into HTML (reflected_input indicator)
//	safe (negative)— an endpoint that echoes NOTHING and reflects NOTHING; the agent
//	                 must not manufacture a finding (the offense analogue of the cloud
//	                 boundary/SCP FP-control)
//
// This is the offense twin of cloudagent's TestAgentNeutralSuite: recall on the positives
// AND specificity on the negative, both with a real model in the loop.
func TestWebAgentNeutralSuite(t *testing.T) {
	if os.Getenv("LLM_BASE_URL") == "" {
		t.Skip("set LLM_BASE_URL (relay/proxy) to run the neutral offense suite")
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		t.Skip("no LLM resolved from the environment")
	}
	model := os.Getenv("LLM_MODEL")

	for _, sc := range offenseScenarios() {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			srv := httptest.NewServer(sc.handler)
			defer srv.Close()

			seeds := []SeedFinding{{Route: srv.URL + sc.seedRoute, Class: sc.class, Tool: "test", Severity: "medium"}}
			rep, err := Investigate(context.Background(), llm, &Context{Target: srv.URL}, Options{
				MaxIters: 8, MaxRequests: 20, SeedFindings: seeds,
			})
			if err != nil {
				t.Fatalf("%s drove the web agent to an error: %v", model, err)
			}

			got := map[string]bool{}
			verified := map[string]bool{}
			for _, f := range rep.Findings {
				got[f.Class] = true
				if f.Verified {
					verified[f.Class] = true
				}
			}
			switch {
			case sc.mustNotRecord:
				if len(rep.Findings) != 0 {
					t.Errorf("[FALSE POSITIVE] %s recorded %d finding(s) on a safe endpoint: %v", sc.name, len(rep.Findings), classesOf(rep))
				} else {
					t.Logf("[correct — declined] %s: agent recorded nothing over %d request(s)", sc.name, rep.Requests)
				}
			default:
				if !got[sc.class] {
					t.Errorf("[MISS] %s: agent did not record a %s finding (found=%v)", sc.name, sc.class, classesOf(rep))
				} else {
					tag := "recorded"
					if verified[sc.class] {
						tag = "recorded+verified"
					}
					t.Logf("[correct — found] %s: %s %s over %d request(s)", sc.name, sc.class, tag, rep.Requests)
				}
			}
		})
	}
}

type offenseScenario struct {
	name          string
	class         string
	seedRoute     string
	handler       http.HandlerFunc
	mustNotRecord bool
}

func classesOf(rep *Report) []string {
	var cs []string
	for _, f := range rep.Findings {
		cs = append(cs, f.Class)
	}
	return cs
}

func offenseScenarios() []offenseScenario {
	return []offenseScenario{
		{
			name: "open_redirect", class: "open_redirect", seedRoute: "/redirect?url=",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<a href="/redirect?url=/home">go</a>`))
			},
		},
		{
			name: "sqli_error_based", class: "sqli", seedRoute: "/item?id=",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/item" {
					id := r.URL.Query().Get("id")
					// A single quote breaks the (simulated) query and leaks a DB error —
					// the exact shape the sql_error extractor grounds on.
					if strings.Contains(id, "'") {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(`SQL error: sqlite3.OperationalError: unrecognized token: near "'": syntax error`))
						return
					}
					_, _ = w.Write([]byte(`{"id":"` + id + `","name":"widget"}`))
					return
				}
				_, _ = w.Write([]byte(`<a href="/item?id=1">item</a>`))
			},
		},
		{
			name: "reflected_xss", class: "xss", seedRoute: "/search?q=",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/search" {
					// Reflects the query verbatim into HTML — reflected_input fires.
					_, _ = w.Write([]byte("<h1>Results for: " + r.URL.Query().Get("q") + "</h1>"))
					return
				}
				_, _ = w.Write([]byte(`<form action="/search"><input name="q"></form>`))
			},
		},
		{
			name: "safe_endpoint", class: "sqli", seedRoute: "/lookup?id=", mustNotRecord: true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				// A parametrised, safe endpoint: it NEVER echoes input and NEVER errors on a
				// quote — there is nothing to ground, so the agent must record nothing.
				if r.URL.Path == "/lookup" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"status":"ok","count":3}`))
					return
				}
				_, _ = w.Write([]byte(`<a href="/lookup?id=1">lookup</a>`))
			},
		},
	}
}
