package grc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOSCALComponentDefinition_ValidShapeAndControls(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	ctrls := map[string][]string{
		"nist_800_53": {"AC-3", "SC-8"},
		"soc2":        {"CC6.1"},
		"empty":       {}, // frameworks with no controls are skipped
	}
	b, err := OSCALComponentDefinition(ctrls, now)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	cd, ok := doc["component-definition"].(map[string]any)
	if !ok {
		t.Fatal("missing root component-definition")
	}
	md := cd["metadata"].(map[string]any)
	if md["oscal-version"] != oscalVersion || md["title"] == "" || md["last-modified"] == "" {
		t.Errorf("metadata wrong: %+v", md)
	}
	comps := cd["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("want 1 component, got %d", len(comps))
	}
	cis := comps[0].(map[string]any)["control-implementations"].([]any)
	if len(cis) != 2 { // nist_800_53 + soc2 (empty skipped)
		t.Fatalf("want 2 control-implementations (empty framework skipped), got %d", len(cis))
	}
	// a control-id is present + sourced
	s := string(b)
	for _, want := range []string{`"control-id": "AC-3"`, `"control-id": "SC-8"`, `"control-id": "CC6.1"`, `"source": "https://www.aicpa.org/tsc"`} {
		if !strings.Contains(s, want) {
			t.Errorf("OSCAL output missing %q", want)
		}
	}
}

func TestOSCALComponentDefinition_Deterministic(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	c := map[string][]string{"soc2": {"CC6.1"}}
	a, _ := OSCALComponentDefinition(c, now)
	b, _ := OSCALComponentDefinition(c, now)
	if string(a) != string(b) {
		t.Error("same input must produce byte-identical OSCAL (deterministic UUIDs)")
	}
}
