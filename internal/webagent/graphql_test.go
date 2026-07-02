package webagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDistillGraphQLSchema_ExtractsSurface: a real introspection response is distilled into queries,
// mutations (flagged as authz targets), and type names.
func TestDistillGraphQLSchema_ExtractsSurface(t *testing.T) {
	body := `{"data":{"__schema":{
	  "queryType":{"name":"Query"},
	  "mutationType":{"name":"Mutation"},
	  "types":[
	    {"name":"Query","kind":"OBJECT","fields":[{"name":"user","args":[{"name":"id"}]},{"name":"me","args":[]}]},
	    {"name":"Mutation","kind":"OBJECT","fields":[{"name":"login","args":[{"name":"user"},{"name":"pass"}]},{"name":"deleteUser","args":[{"name":"id"}]}]},
	    {"name":"User","kind":"OBJECT","fields":[{"name":"id","args":[]}]},
	    {"name":"__Type","kind":"OBJECT","fields":[]}
	  ]}}}`
	got, ok := distillGraphQLSchema(body)
	if !ok {
		t.Fatal("valid introspection not distilled")
	}
	for _, want := range []string{"user(id)", "login(user,pass)", "deleteUser(id)", "mutations", "User"} {
		if !strings.Contains(got, want) {
			t.Errorf("distilled schema missing %q\n  got: %s", want, got)
		}
	}
	// introspection meta-types must not leak into the type list
	if strings.Contains(got, "__Type") {
		t.Errorf("introspection meta-type leaked into surface: %s", got)
	}
}

// TestDistillGraphQLSchema_QuietOnNonSchema: a non-GraphQL / introspection-disabled body yields nothing
// (never invents a schema — §10).
func TestDistillGraphQLSchema_QuietOnNonSchema(t *testing.T) {
	for _, b := range []string{
		`{"errors":[{"message":"introspection is disabled"}]}`,
		`<html>not graphql</html>`,
		`{"data":{"__schema":{"types":[]}}}`,
		``,
	} {
		if got, ok := distillGraphQLSchema(b); ok {
			t.Errorf("invented a schema from %q → %q", b, got)
		}
	}
}

// TestTGraphQL_LiveIntrospection drives the tool against a fake /graphql server: it POSTs the
// introspection query and surfaces the schema; the request is recorded as a Turn (evidence).
func TestTGraphQL_LiveIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "__schema") { // it must send the introspection query
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[`+
			`{"name":"Query","kind":"OBJECT","fields":[{"name":"secretFlag","args":[]}]},`+
			`{"name":"Mutation","kind":"OBJECT","fields":[{"name":"resetPassword","args":[{"name":"email"}]}]}]}}}`)
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 5, 0)
	cc.ctx = context.Background()
	out := tGraphQL(cc, map[string]any{}) // no url → defaults to <target>/graphql
	for _, want := range []string{"secretFlag", "resetPassword(email)", "mutations"} {
		if !strings.Contains(out, want) {
			t.Errorf("tool output missing %q\n  got: %s", want, out)
		}
	}
	if len(cc.History) != 1 || cc.History[0].Method != "POST" {
		t.Errorf("introspection request not recorded as a Turn: %+v", cc.History)
	}
	if !strings.Contains(cc.History[0].Body, "__schema") {
		t.Errorf("recorded Turn body is not the introspection query: %s", cc.History[0].Body)
	}
}

// sanity: the introspection query we ship is valid JSON-embeddable (marshals without error into a body).
func TestGraphQLIntrospectionQuery_Embeds(t *testing.T) {
	b, err := json.Marshal(map[string]string{"query": gqlIntrospectionQuery})
	if err != nil || !strings.Contains(string(b), "__schema") {
		t.Fatalf("introspection query does not embed cleanly: %v (%s)", err, b)
	}
}
