// Package cloudsearch is "search your cloud like a database" (Aikido /Cloud parity) over the inventory the
// engine ALREADY builds — `cloudgraph.Inventory` (resources + their relationships). The attack-path engine
// assembles this graph to reason about exposure and privesc; cloudsearch exposes it as a queryable surface
// so an operator can instantly answer "which storage is public?", "what can reach this database?", "every
// privileged principal in us-east-1" — without restarting a scan.
//
// It is pure + deterministic + grounded (§10): every result is a real resource/edge from the supplied
// inventory; a predicate matches only what the inventory states (e.g. `public` flags only resources the
// ingest marked internet-exposed). No fabrication, no inference. An empty inventory yields no results.
package cloudsearch

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// Query is the filter set — the "WHERE clause" over the cloud inventory. Zero value matches everything
// (capped by Limit). The *bool fields are tri-state: nil = don't filter, &true / &false = require that.
type Query struct {
	Text       string `json:"text,omitempty"`       // case-insensitive substring on id/name/type/tags
	Kind       string `json:"kind,omitempty"`       // resource kind: compute|storage|principal|network|...
	Type       string `json:"type,omitempty"`       // case-insensitive substring on the provider type (s3, ec2, iam_role)
	Region     string `json:"region,omitempty"`     // exact region match
	Public     *bool  `json:"public,omitempty"`     // internet-exposed?
	Privileged *bool  `json:"privileged,omitempty"` // privileged identity?
	Sensitive  *bool  `json:"sensitive,omitempty"`  // holds sensitive data (PII/secrets/prod)?
	Tag        string `json:"tag,omitempty"`        // "key=value" or just "key" (presence)
	Limit      int    `json:"limit,omitempty"`      // cap returned matches (default 100)
}

// Match is one resource plus its immediate relationships (the "JOIN") — what it can reach and what can
// reach it, derived from the inventory's real edges.
type Match struct {
	cloudgraph.InvResource
	Reaches   []string `json:"reaches,omitempty"`    // resource ids THIS one points at (network/grant/trust/pass/privesc/runs_as/trigger)
	ReachedBy []string `json:"reached_by,omitempty"` // resource ids that point AT this one
}

// Results is the query response.
type Results struct {
	Matches  []Match `json:"matches"`
	Total    int     `json:"total"`    // total matches before Limit
	Returned int     `json:"returned"` // len(Matches)
}

// Search runs the query over the inventory.
func Search(inv cloudgraph.Inventory, q Query) Results {
	out, in := adjacency(inv)
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}

	res := Results{Matches: []Match{}}
	for _, r := range inv.Resources {
		if !match(r, q) {
			continue
		}
		res.Total++
		if len(res.Matches) >= limit {
			continue // keep counting Total, stop collecting
		}
		res.Matches = append(res.Matches, Match{
			InvResource: r,
			Reaches:     sortedUnique(out[r.ID]),
			ReachedBy:   sortedUnique(in[r.ID]),
		})
	}
	res.Returned = len(res.Matches)
	return res
}

func match(r cloudgraph.InvResource, q Query) bool {
	if q.Kind != "" && !strings.EqualFold(string(r.Kind), q.Kind) {
		return false
	}
	if q.Type != "" && !strings.Contains(strings.ToLower(r.Type), strings.ToLower(q.Type)) {
		return false
	}
	if q.Region != "" && !strings.EqualFold(r.Region, q.Region) {
		return false
	}
	if q.Public != nil && r.Public != *q.Public {
		return false
	}
	if q.Privileged != nil && r.Privileged != *q.Privileged {
		return false
	}
	if q.Sensitive != nil {
		has := r.Sensitive != cloudgraph.SensNone
		if has != *q.Sensitive {
			return false
		}
	}
	if q.Tag != "" && !tagMatch(r.Tags, q.Tag) {
		return false
	}
	if q.Text != "" && !textMatch(r, q.Text) {
		return false
	}
	return true
}

func textMatch(r cloudgraph.InvResource, text string) bool {
	t := strings.ToLower(text)
	if strings.Contains(strings.ToLower(r.ID), t) ||
		strings.Contains(strings.ToLower(r.Name), t) ||
		strings.Contains(strings.ToLower(r.Type), t) {
		return true
	}
	for k, v := range r.Tags {
		if strings.Contains(strings.ToLower(k), t) || strings.Contains(strings.ToLower(v), t) {
			return true
		}
	}
	return false
}

func tagMatch(tags map[string]string, spec string) bool {
	k, v, hasVal := strings.Cut(spec, "=")
	val, present := tags[k]
	if !present {
		return false
	}
	return !hasVal || val == v
}

// adjacency collapses every relationship list into out[from] / in[to] id-sets.
func adjacency(inv cloudgraph.Inventory) (out, in map[string][]string) {
	out, in = map[string][]string{}, map[string][]string{}
	add := func(from, to string) {
		if from == "" || to == "" {
			return
		}
		out[from] = append(out[from], to)
		in[to] = append(in[to], from)
	}
	for _, e := range inv.Reaches {
		add(e.From, e.To)
	}
	for _, e := range inv.Grants {
		add(e.Principal, e.Resource)
	}
	for _, e := range inv.Trusts {
		add(e.Principal, e.Role)
	}
	for _, e := range inv.Passes {
		add(e.Principal, e.Role)
	}
	for _, e := range inv.Privescs {
		add(e.Principal, e.Target)
	}
	for _, e := range inv.RunsAs {
		add(e.Compute, e.Principal)
	}
	for _, e := range inv.Triggers {
		add(e.Source, e.Compute)
	}
	return out, in
}

func sortedUnique(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
