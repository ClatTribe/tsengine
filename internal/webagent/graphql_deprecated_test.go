package webagent

import (
	"strings"
	"testing"
)

// TestGraphQLIntrospectionQuery_RequestsDeprecated: the introspection query must ask for deprecated
// fields. Per the GraphQL spec, __type.fields takes `includeDeprecated: Boolean = false`, so a
// spec-compliant server OMITS deprecated operations by default. A deprecated-but-still-wired mutation
// (a legacy endpoint kept for backwards-compat — and frequently the LEAST-protected, a prime
// authz/IDOR target) would then be invisible in the distilled schema. The standard introspection query
// (GraphiQL/Apollo) requests includeDeprecated:true; the minimal query here dropped it.
func TestGraphQLIntrospectionQuery_RequestsDeprecated(t *testing.T) {
	q := strings.ReplaceAll(gqlIntrospectionQuery, " ", "")
	if !strings.Contains(q, "fields(includeDeprecated:true)") {
		t.Errorf("introspection query does not request deprecated fields — deprecated (legacy, often less-protected) operations are hidden by the server default:\n%s", gqlIntrospectionQuery)
	}
}

// TestDistillGraphQL_SurfacesDeprecatedMutation: given an introspection response that includes a
// deprecated mutation (as a spec server returns once includeDeprecated:true is sent), the distiller must
// surface it. Guards that the parser itself never drops mutations/types — the fix is in the query, but
// the end-to-end value is that the deprecated op reaches the agent's lead.
func TestDistillGraphQL_SurfacesDeprecatedMutation(t *testing.T) {
	resp := `{"data":{"__schema":{
		"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
		"types":[
			{"name":"Query","kind":"OBJECT","fields":[{"name":"me","args":[]}]},
			{"name":"Mutation","kind":"OBJECT","fields":[{"name":"deleteUserLegacy","args":[{"name":"id"}]}]},
			{"name":"User","kind":"OBJECT","fields":[{"name":"email","args":[]}]}
		]}}}`
	out, ok := distillGraphQLSchema(resp)
	if !ok {
		t.Fatal("valid introspection response was not distilled")
	}
	if !strings.Contains(out, "deleteUserLegacy") {
		t.Errorf("deprecated mutation dropped from the distilled schema:\n%s", out)
	}
	if !strings.Contains(out, "User") {
		t.Errorf("object type dropped from the distilled schema:\n%s", out)
	}
}
