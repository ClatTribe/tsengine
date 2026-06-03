// Command webrange serves an emulated, procedurally-generated vulnerable web
// application (internal/webrange) for testing the web agent against an independent
// ground-truth answer key.
//
//	webrange --seed 7 --addr 127.0.0.1:8099 --manifest answer_key.json
//
// Point the agent at it:
//
//	tsengine web-investigate --target http://127.0.0.1:8099   # real LLM brain
//
// or score it deterministically with `go test ./internal/webrange/`. The manifest
// (the answer key) is written to --manifest but NOT printed, so the run can be
// blind: serve, let the agent sweep, then score its findings against the file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/ClatTribe/tsengine/internal/webrange"
)

func main() {
	seed := flag.Int64("seed", 1, "generation seed (reproducible range)")
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	n := flag.Int("n", 12, "number of param-bearing routes")
	decoyFrac := flag.Float64("decoy-frac", 0.4, "fraction of routes that are safe decoys")
	manifestPath := flag.String("manifest", "", "write the ground-truth answer key (manifest) to this JSON file")
	reveal := flag.Bool("reveal", false, "print the answer key to stderr (non-blind)")
	flag.Parse()

	rg := webrange.Generate(*seed, webrange.Opts{N: *n, DecoyFrac: *decoyFrac})
	m := rg.Manifest

	if *manifestPath != "" {
		data, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "webrange: marshal manifest: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*manifestPath, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "webrange: write manifest: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[webrange] answer key → %s\n", *manifestPath)
	}

	fmt.Fprintf(os.Stderr, "[webrange] seed=%d  routes=%d  exploitable=%d  decoys=%d  serving on http://%s\n",
		*seed, len(m.Targets), m.Exploitable, m.Decoys, *addr)
	for _, s := range rg.Surface() {
		fmt.Fprintf(os.Stderr, "  http://%s%s\n", *addr, s)
	}
	if *reveal {
		fmt.Fprintln(os.Stderr, "[webrange] ANSWER KEY (--reveal):")
		for _, t := range m.Targets {
			kind := "DECOY"
			if t.Exploitable {
				kind = "REAL "
			}
			waf := ""
			if t.WAF {
				waf = " [WAF]"
			}
			fmt.Fprintf(os.Stderr, "  %s %-18s %s?%s=%s\n", kind, t.Class, t.Path, t.Param, waf)
		}
	}

	srv := &http.Server{Addr: *addr, Handler: rg.Handler()} //nolint:gosec // local test fixture
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "webrange: %v\n", err)
		os.Exit(1)
	}
}
