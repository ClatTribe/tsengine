package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// triageCmd runs the alert-triage benchmark (the AI-SOC metric: TP-detection + FP-rejection +
// calibration against adversarial decoys) over a noisy estate. Deterministic, credential-free.
func triageCmd(argv []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	r := bench.RunTriageBench()
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(bench.RenderTriageMarkdown(r))
	if !r.Pass() {
		return fmt.Errorf("triage FAILED: missed=%v mis-escalated=%v", r.MissedThreats, r.MisEscalated)
	}
	return nil
}
