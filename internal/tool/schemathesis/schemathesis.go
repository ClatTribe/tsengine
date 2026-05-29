// Package schemathesis wraps schemathesis (property-based API fuzzing
// driven by an OpenAPI/GraphQL schema) as a tsengine Tool for the api
// asset. It derives test cases from the spec and asserts the API's
// responses conform — catching 500s, schema violations, and contract
// breaks no signature scanner finds. Registers via init().
package schemathesis

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Schemathesis is the tool.Tool implementation.
type Schemathesis struct{}

// New constructs a Schemathesis wrapper.
func New() *Schemathesis { return &Schemathesis{} }

func (*Schemathesis) Name() string              { return "schemathesis" }
func (*Schemathesis) SandboxExecution() bool    { return true }
func (*Schemathesis) MITRETechniques() []string { return []string{"T1190"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Schemathesis) KnownArgs() []string { return []string{"spec_url", "max_examples"} }

// Run fuzzes an API from its schema. Recognized args:
//
//	"spec_url"     string — required, the OpenAPI/GraphQL schema URL.
//	"max_examples" int    — optional, hypothesis examples per operation.
//
// Failures are parsed from a JUnit XML report (schemathesis's machine
// output) into findings.
func (*Schemathesis) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	specURL, _ := args["spec_url"].(string)
	if strings.TrimSpace(specURL) == "" {
		return tool.Result{}, errors.New("schemathesis: missing required arg 'spec_url'")
	}
	f, err := os.CreateTemp("", "schemathesis-*.xml")
	if err != nil {
		return tool.Result{}, err
	}
	junit := f.Name()
	_ = f.Close()
	defer os.Remove(junit)

	cli := []string{"run", specURL, "--checks", "all", "--junit-xml", junit}
	if n, ok := args["max_examples"].(int); ok && n > 0 {
		cli = append(cli, fmt.Sprintf("--hypothesis-max-examples=%d", n))
	}
	cmd := exec.CommandContext(ctx, "schemathesis", cli...)
	combined, runErr := cmd.CombinedOutput()

	report, rerr := os.ReadFile(junit) //nolint:gosec // temp file we created
	if rerr != nil || len(report) == 0 {
		// No report — schemathesis failed to load the schema. Degrade.
		return tool.Result{Output: string(combined)}, nil
	}
	_ = runErr
	return tool.Result{Output: string(combined), Findings: parse(report)}, nil
}

// junitSuites mirrors the JUnit XML schemathesis emits.
type junitSuites struct {
	Suites []struct {
		Cases []struct {
			Name    string `xml:"name,attr"`
			Failure *struct {
				Message string `xml:"message,attr"`
			} `xml:"failure"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func parse(report []byte) []types.SandboxEmittedFinding {
	var js junitSuites
	if xml.Unmarshal(report, &js) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, suite := range js.Suites {
		for _, tc := range suite.Cases {
			var msg string
			switch {
			case tc.Failure != nil:
				msg = tc.Failure.Message
			case tc.Error != nil:
				msg = tc.Error.Message
			default:
				continue // passing case
			}
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "schemathesis::contract-violation",
				Tool:            "schemathesis",
				Severity:        types.SeverityMedium,
				Endpoint:        tc.Name, // "METHOD /path"
				Title:           "API contract/robustness violation: " + tc.Name,
				Description:     truncate(msg, 500),
				MITRETechniques: []string{"T1190"},
			})
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func init() { tool.Register(New()) }
