// Command sast-score scores a local semgrep run against the OWASP Benchmark ground truth
// using tsengine's OWN scorer (internal/bench.ScoreSast) — so the Youden number is exactly
// what `tsbench sast` would produce, just with semgrep run on the host instead of in the
// sandbox. Reproduces the repository asset's semgrep config (p/security-audit + p/secrets)
// and CWE/endpoint extraction. Dev/bench tool.
//
//	semgrep --config p/security-audit --config p/secrets --json -o sg.json <benchmark-src>
//	go run ./cmd/sast-score sg.json expectedresults-1.2.csv
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var cwePattern = regexp.MustCompile(`CWE-\d+`)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: sast-score <semgrep.json> <expectedresults.csv>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1]) //nolint:gosec
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var sg struct {
		Results []struct {
			Path  string `json:"path"`
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Metadata struct {
					CWE json.RawMessage `json:"cwe"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &sg); err != nil {
		fmt.Fprintln(os.Stderr, "parse semgrep json:", err)
		os.Exit(1)
	}

	scan := &types.Scan{}
	for _, r := range sg.Results {
		cwes := cwePattern.FindAllString(string(r.Extra.Metadata.CWE), -1)
		ep := r.Path
		if r.Start.Line > 0 {
			ep = fmt.Sprintf("%s:%d", r.Path, r.Start.Line)
		}
		scan.FindingsRaw = append(scan.FindingsRaw, types.Finding{CWE: cwes, Endpoint: ep})
	}

	cases, err := bench.LoadSastCases(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rep := bench.ScoreSast(cases, scan)
	fmt.Printf("(semgrep findings: %d · ground-truth cases: %d)\n", len(scan.FindingsRaw), len(cases))
	fmt.Print(bench.RenderSast(rep))
}
