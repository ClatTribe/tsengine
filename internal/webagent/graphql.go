package webagent

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
	"sort"
	"strings"
)

// graphql.go gives the agent the GraphQL recon step: POST the standard introspection query to a
// /graphql endpoint and DISTILL the returned schema into a compact lead — the queries, the
// state-changing mutations (prime authz/IDOR targets), and the object type names. A GraphQL API's whole
// surface is one introspection call away, but the raw response is a huge JSON blob that blows the
// snippet cap, so a blind agent never learns the operations exist. This is recon TOOLING (the agent's
// hands), not a detector (§13); the schema is real server data used only as a LEAD (§10), and a finding
// still rides on the deterministic indicators of the requests the agent then crafts.

// gqlIntrospectionQuery asks for just enough to enumerate the surface: query/mutation root names, and
// each type's fields + arg names. Kept minimal (no nested type refs) so the response stays parseable.
// fields(includeDeprecated:true) is REQUIRED: the spec default is `includeDeprecated: false`, so a
// compliant server otherwise OMITS deprecated operations — and a deprecated-but-still-wired mutation
// (a legacy endpoint kept for backwards-compat) is frequently the LEAST-protected authz/IDOR target.
// This matches the standard GraphiQL/Apollo introspection query.
const gqlIntrospectionQuery = `{__schema{queryType{name} mutationType{name} types{name kind fields(includeDeprecated:true){name args{name}}}}}`

type gqlTypeRef struct {
	Name string `json:"name"`
}

type gqlType struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields []struct {
		Name string `json:"name"`
		Args []struct {
			Name string `json:"name"`
		} `json:"args"`
	} `json:"fields"`
}

type gqlIntrospection struct {
	Data struct {
		Schema struct {
			QueryType    *gqlTypeRef `json:"queryType"`
			MutationType *gqlTypeRef `json:"mutationType"`
			Types        []gqlType   `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// tGraphQL fires the introspection request through the scoped Requester (budget-counted + allowlisted,
// like send_request), records the turn for evidence, and returns the distilled schema.
func tGraphQL(cc *Context, args map[string]any) string {
	url := strings.TrimSpace(argStr(args, "url"))
	if url == "" {
		if cc.Target == "" {
			return "ERROR: url is required (the GraphQL endpoint, e.g. https://target/graphql)"
		}
		url = strings.TrimRight(cc.Target, "/") + "/graphql"
	}
	bodyBytes, _ := json.Marshal(map[string]string{"query": gqlIntrospectionQuery})
	body := string(bodyBytes)
	hdr := map[string]string{"Content-Type": "application/json"}
	resp, err := cc.req.Send(cc.ctx, "POST", url, body, hdr)
	if err != nil {
		return "REQUEST FAILED: " + err.Error()
	}
	// GraphQL mounts on Starlette / FastAPI / Django commonly 307/308-redirect a missing trailing slash
	// (/graphql -> /graphql/) — a method+body-preserving redirect. The Requester doesn't auto-follow
	// (that's for open-redirect detection on 301/302), so follow ONE such redirect here, else the most
	// common GraphQL setup silently returns no schema.
	for hops := 0; hops < 2 && resp.Status >= 300 && resp.Status < 400 && resp.Location != ""; hops++ {
		loc := resp.Location
		if b, e := neturl.Parse(url); e == nil {
			if r, e2 := neturl.Parse(loc); e2 == nil {
				loc = b.ResolveReference(r).String()
			}
		}
		if loc == url {
			break
		}
		r2, e := cc.req.Send(cc.ctx, "POST", loc, body, hdr)
		if e != nil {
			break
		}
		resp, url = r2, loc
	}
	cc.turnN++
	// head+tail, not head-only: a large introspection/query response can carry the proving data
	// (a leaked field value) near the end, so keep the tail (the #807 fix, applied here too).
	ev := headTail(resp.Body, evidenceBodyCap-evidenceBodyTail, evidenceBodyTail)
	cc.History = append(cc.History, Turn{
		ID: fmt.Sprintf("t-%03d", cc.turnN), Method: "POST", URL: url,
		Body: body, Status: resp.Status, Elapsed: resp.Elapsed.String(), RespSnippet: ev,
	})
	summary, ok := distillGraphQLSchema(resp.Body)
	if !ok {
		return fmt.Sprintf("t-%03d  status=%d — introspection returned no schema (it may be DISABLED, or this isn't a GraphQL endpoint). Try known queries/mutations by hand.", cc.turnN, resp.Status)
	}
	return fmt.Sprintf("t-%03d  status=%d  %s", cc.turnN, resp.Status, summary)
}

// distillGraphQLSchema turns an introspection response into a one-line surface summary, or ("",false)
// when the body carries no usable schema (introspection disabled / not GraphQL).
func distillGraphQLSchema(respBody string) (string, bool) {
	var r gqlIntrospection
	if err := json.Unmarshal([]byte(respBody), &r); err != nil {
		return "", false
	}
	types := r.Data.Schema.Types
	if len(types) == 0 {
		return "", false
	}
	qName := "Query"
	if r.Data.Schema.QueryType != nil && r.Data.Schema.QueryType.Name != "" {
		qName = r.Data.Schema.QueryType.Name
	}
	mName := "Mutation"
	if r.Data.Schema.MutationType != nil && r.Data.Schema.MutationType.Name != "" {
		mName = r.Data.Schema.MutationType.Name
	}
	byName := map[string]gqlType{}
	var objectNames []string
	for _, ty := range types {
		byName[ty.Name] = ty
		if ty.Kind == "OBJECT" && !strings.HasPrefix(ty.Name, "__") && ty.Name != qName && ty.Name != mName {
			objectNames = append(objectNames, ty.Name)
		}
	}
	fmtFields := func(t gqlType) []string {
		out := make([]string, 0, len(t.Fields))
		for _, f := range t.Fields {
			an := make([]string, 0, len(f.Args))
			for _, a := range f.Args {
				an = append(an, a.Name)
			}
			if len(an) > 0 {
				out = append(out, f.Name+"("+strings.Join(an, ",")+")")
			} else {
				out = append(out, f.Name)
			}
		}
		return out
	}
	var parts []string
	if q, ok := byName[qName]; ok && len(q.Fields) > 0 {
		parts = append(parts, "queries: "+capList(fmtFields(q), 20))
	}
	if m, ok := byName[mName]; ok && len(m.Fields) > 0 {
		parts = append(parts, "mutations (state-changing — prime authz/IDOR targets): "+capList(fmtFields(m), 20))
	}
	if len(objectNames) > 0 {
		sort.Strings(objectNames)
		parts = append(parts, "types: "+capList(objectNames, 20))
	}
	if len(parts) == 0 {
		return "", false
	}
	return "GraphQL schema (introspection): " + strings.Join(parts, " | "), true
}

// capList joins a slice, capping at max with a "(+N more)" tail.
func capList(xs []string, max int) string {
	extra := 0
	if len(xs) > max {
		extra = len(xs) - max
		xs = xs[:max]
	}
	out := strings.Join(xs, ", ")
	if extra > 0 {
		out += ", (+" + itoa(extra) + " more)"
	}
	return out
}
