// Package inql wraps doyensec/inql (GraphQL introspection + audit) as a
// tsengine depth Tool for the api asset. It fills a gap nuclei/schemathesis
// can't: pulling a GraphQL endpoint's full schema via introspection and
// flagging that introspection is enabled (a production misconfig that hands
// attackers the entire API surface). Fired by the escalation engine when a
// /graphql endpoint appears. Registers via init().
package inql

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// execInql shells out to the inql CLI for an introspection dump.
func execInql(ctx context.Context, target string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "inql", "-t", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// inql may exit non-zero but still print introspection — return
			// the output for the heuristic to judge.
			return out, nil
		}
		return nil, err
	}
	return out, nil
}

// INQL is the tool.Tool implementation.
type INQL struct{}

// New constructs an INQL wrapper.
func New() *INQL { return &INQL{} }

func (*INQL) Name() string              { return "inql" }
func (*INQL) SandboxExecution() bool    { return true }
func (*INQL) MITRETechniques() []string { return []string{"T1595"} }

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*INQL) KnownArgs() []string { return []string{"target"} }

// runner is swapped in tests; production shells out to inql.
var runner = func(ctx context.Context, target string) ([]byte, error) {
	return execInql(ctx, target)
}

// Run introspects a GraphQL endpoint. Recognized args:
//
//	"target" string — required, the /graphql endpoint URL.
//
// If introspection returns a schema, that's itself a finding (introspection
// should be disabled in production); the schema rides in Output.
func (*INQL) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return tool.Result{}, errors.New("inql: missing required arg 'target'")
	}
	out, err := runner(ctx, target)
	if err != nil {
		return tool.Result{Output: "inql: " + err.Error()}, nil
	}
	return tool.Result{Output: string(out), Findings: parse(out, target)}, nil
}

// introspectionEnabled is the heuristic that the endpoint answered an
// introspection query (schema dump present).
func introspectionEnabled(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "__schema") ||
		strings.Contains(s, "queries") && strings.Contains(s, "mutations") ||
		strings.Contains(s, "introspection")
}

func parse(out []byte, target string) []types.SandboxEmittedFinding {
	if !introspectionEnabled(out) {
		return nil
	}
	return []types.SandboxEmittedFinding{{
		RuleID:          "inql::introspection-enabled",
		Tool:            "inql",
		Severity:        types.SeverityMedium,
		Endpoint:        target,
		Title:           "GraphQL introspection enabled",
		Description:     "The endpoint answers introspection queries, exposing the full schema (queries/mutations/types) to attackers. Disable introspection in production.",
		MITRETechniques: []string{"T1595"},
	}}
}

func init() { tool.Register(New()) }
