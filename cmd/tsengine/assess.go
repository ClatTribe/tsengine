package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/platformapi"
)

// tsengine assess — the public /v1/assess check, run in batch from the operator's own machine.
//
// The scan-led outbound motion runs ~50 prospect domains a week through the same eight checks the
// /scan page runs, and quotes the failing ones. Doing that against the public endpoint trips its own
// 20-per-IP limiter, which guards the page against strangers, not the operator. This calls the same
// function the endpoint calls (platformapi.AssessDomain), so an email can never quote a finding the
// prospect's own /scan?domain= link would not show. Read-only and public-safe by construction.
func runAssess(argv []string) error {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	var domains multiFlag
	fs.Var(&domains, "domain", "domain to assess (repeatable)")
	file := fs.String("domains", "", "file with one domain per line (# comments allowed; '-' = stdin)")
	asJSON := fs.Bool("json", false, "emit a JSON array of full reports (what /v1/assess returns) instead of a table")
	conc := fs.Int("concurrency", 4, "domains assessed at once")
	timeout := fs.Duration("timeout", 25*time.Second, "per-domain budget")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	list := append([]string(nil), domains...)
	if *file != "" {
		more, err := readDomainList(*file)
		if err != nil {
			return err
		}
		list = append(list, more...)
	}
	if len(list) == 0 {
		return errors.New("nothing to assess: pass --domain <d> or --domains <file>")
	}
	if *conc < 1 {
		*conc = 1
	}

	type row struct {
		Domain string                    `json:"domain"`
		Report *platformapi.AssessReport `json:"report,omitempty"`
		Error  string                    `json:"error,omitempty"`
	}
	rows := make([]row, len(list))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *conc)
	for i, d := range list {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			defer cancel()
			rep, err := platformapi.AssessDomain(ctx, d)
			rows[i] = row{Domain: d}
			if err != nil {
				rows[i].Error = err.Error()
				return
			}
			rows[i].Report = &rep
		}(i, d)
	}
	wg.Wait()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	// Table: one line per domain, worst grade first so the list reads as a call sheet. A domain
	// that could not be assessed says so on its own line — it is not a clean one.
	sort.SliceStable(rows, func(a, b int) bool {
		ga, gb := rows[a].Report, rows[b].Report
		if ga == nil || gb == nil {
			return ga == nil && gb != nil
		}
		return ga.Score < gb.Score
	})
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "%-32s %-5s %-6s %s\n", "DOMAIN", "GRADE", "SCORE", "FAILING CHECKS")
	for _, r := range rows {
		if r.Report == nil {
			fmt.Fprintf(w, "%-32s %-5s %-6s %s\n", r.Domain, "—", "—", "not assessed: "+r.Error)
			continue
		}
		var failing []string
		for _, c := range r.Report.Checks {
			if !c.OK {
				failing = append(failing, c.Name)
			}
		}
		fail := strings.Join(failing, ", ")
		if fail == "" {
			fail = "none of the " + fmt.Sprint(len(r.Report.Checks)) + " checks"
		}
		fmt.Fprintf(w, "%-32s %-5s %-6d %s\n", r.Report.Domain, r.Report.Grade, r.Report.Score, fail)
	}
	return nil
}

// readDomainList reads one domain per line; blank lines and #-comments are skipped.
func readDomainList(path string) ([]string, error) {
	var rd io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rd = f
	}
	var out []string
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
