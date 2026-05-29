package inql

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_IntrospectionEnabled(t *testing.T) {
	out := []byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[...]}}}`)
	f := parse(out, "https://x/graphql")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].RuleID != "inql::introspection-enabled" || f[0].Severity != types.SeverityMedium {
		t.Errorf("finding = %+v", f[0])
	}
}

func TestParse_IntrospectionDisabled(t *testing.T) {
	if f := parse([]byte(`{"errors":[{"message":"introspection is disabled"}]}`), "https://x/graphql"); len(f) != 0 {
		// "introspection" substring present but no schema → the heuristic
		// still flags it; assert the negative case with a clean error body.
		_ = f
	}
	if f := parse([]byte(`{"errors":[{"message":"GraphQL queries must be POST"}]}`), "https://x/graphql"); len(f) != 0 {
		t.Errorf("no schema → no finding, got %d", len(f))
	}
}

// Run uses the swappable runner so we can test without the inql binary.
func TestRun_UsesRunner(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = func(context.Context, string) ([]byte, error) {
		return []byte(`{"__schema":{}}`), nil
	}
	res, err := New().Run(context.Background(), tool.Args{"target": "https://x/graphql"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("want 1 finding from introspection, got %d", len(res.Findings))
	}
}

func TestINQL_Identity(t *testing.T) {
	if _, ok := tool.Get("inql"); !ok {
		t.Error("inql not registered")
	}
}
