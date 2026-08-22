package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/improveloop"
)

// journal is the on-disk state the driver reasons over: what we measured, what rounds have run, and
// the plan bounding them.
//
// A FILE, not memory, because the package says why: "a driver holding its state in memory cannot be
// audited afterwards, and this is the machinery that decides where engineering effort goes." Next is
// a pure function of this journal, so the same file always yields the same decision and a past
// decision can be replayed and disputed.
type journal struct {
	Baseline []improveloop.Measurement `json:"baseline"`
	Rounds   []improveloop.Round       `json:"rounds"`
	Plan     improveloop.Plan          `json:"plan"`
}

// improveCmd decides which capability to work on next, or that the loop should stop.
//
// internal/improveloop is ADR 0018 item 2 — the simulation improvement loop — and it had NO caller:
// Compare, Weakest, HoldoutSeeds and Next were reachable only from their own tests, so the machinery
// that decides where engineering effort goes could not be run. This is the entry point.
//
// It decides; it does not improve. The substrate-improvement step itself is a person's or an agent's
// (the package is explicit that nothing in it writes code). What the driver owns is the discipline
// around that step: the target is picked deterministically as the WEAKEST eligible capability rather
// than by preference, the seeds handed to a round are disjoint from what that capability was already
// tuned against, and a round that does not buy enough improvement per dollar ends the loop.
func improveCmd(argv []string) error {
	fs := flag.NewFlagSet("improve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("journal", "", "path to the improvement journal JSON (baseline + rounds + plan)")
	asJSON := fs.Bool("json", false, "emit the decision as JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if strings.TrimSpace(*path) == "" {
		return fmt.Errorf("--journal is required: the decision is a pure function of the recorded " +
			"journal, and inventing a baseline would make the answer unauditable")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		// Refused rather than defaulted. An unreadable journal must not become an empty one: Next
		// would answer "nothing to improve", which is the clean-because-we-did-not-look answer.
		return fmt.Errorf("cannot read the journal at %s: %w", *path, err)
	}
	var j journal
	if err := json.Unmarshal(raw, &j); err != nil {
		return fmt.Errorf("the journal at %s is not valid JSON (%w) — refusing to decide from a "+
			"file we could not read", *path, err)
	}

	d := improveloop.Next(j.Baseline, j.Rounds, j.Plan)
	if *asJSON {
		out, merr := json.MarshalIndent(d, "", "  ")
		if merr != nil {
			return merr
		}
		fmt.Println(string(out))
		return nil
	}
	fmt.Print(renderDecision(d, len(j.Baseline), len(j.Rounds)))
	return nil
}

func renderDecision(d improveloop.Decision, capabilities, rounds int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "improvement loop — %d capabilities, %d rounds run\n\n", capabilities, rounds)
	if d.Done {
		fmt.Fprintf(&b, "STOP: %s\n", d.Why)
	} else {
		fmt.Fprintf(&b, "NEXT: %s (score %.3f)\n", d.Target.Capability, d.Target.Score)
		fmt.Fprintf(&b, "  why:     %s\n", d.Why)
		if len(d.Holdout) > 0 {
			fmt.Fprintf(&b, "  holdout: %v\n", d.Holdout)
		}
	}
	// Blocked is printed in BOTH branches and never summarised away. A loop that quietly stops
	// working on something is indistinguishable from one that finished it.
	if len(d.Blocked) > 0 {
		keys := make([]string, 0, len(d.Blocked))
		for k := range d.Blocked {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "\nnot eligible for further rounds:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-28s %s\n", k, d.Blocked[k])
		}
	}
	return b.String()
}
