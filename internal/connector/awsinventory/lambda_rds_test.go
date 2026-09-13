package awsinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// Functions and databases enter the graph with the same discipline as instances and buckets: a
// function URL with no auth IS the internet edge (nothing sits in front of it), while a database's
// public endpoint is only reachability when a security group opens its port — and sensitivity is
// declared, never inferred.
func TestBuild_FunctionsAndDatabases(t *testing.T) {
	raw := RawAWS{
		AccountID: "1",
		SGs: []RawSecurityGroup{
			{ID: "sg-open", IngressJSON: `[{"proto":"tcp","cidr":"0.0.0.0/0","port_from":5432,"port_to":5432}]`},
			{ID: "sg-corp", IngressJSON: `[{"proto":"tcp","cidr":"10.0.0.0/8","port_from":3306,"port_to":3306}]`},
		},
		Functions: []RawFunction{
			{ARN: "arn:aws:lambda:us-east-1:1:function:hook", Name: "hook", RoleARN: "arn:aws:iam::1:role/hook-exec", PublicURL: true},
			{ARN: "arn:aws:lambda:us-east-1:1:function:nightly", Name: "nightly", RoleARN: "arn:aws:iam::1:role/nightly-exec"},
		},
		Databases: []RawDatabase{
			{ARN: "arn:aws:rds:us-east-1:1:db:customers", ID: "customers", Engine: "postgres", Public: true, Port: 5432, SGIDs: []string{"sg-open"}, Sensitive: true},
			{ARN: "arn:aws:rds:us-east-1:1:db:metrics", ID: "metrics", Engine: "mysql", Public: true, Port: 3306, SGIDs: []string{"sg-corp"}, Encrypted: true},
			{ARN: "arn:aws:rds:us-east-1:1:db:noport", ID: "noport", Public: true, SGIDs: []string{"sg-open"}},
		},
	}
	inv := Build(raw)

	byID := map[string]cloudgraph.InvResource{}
	for _, r := range inv.Resources {
		byID[r.ID] = r
	}
	if r := byID["arn:aws:lambda:us-east-1:1:function:hook"]; r.Type != "lambda_function" || !r.Public {
		t.Errorf("public-URL function: %+v", r)
	}
	if r := byID["arn:aws:rds:us-east-1:1:db:customers"]; r.Kind != cloudgraph.KindData || r.Sensitive != cloudgraph.SensHigh || r.Tags["encrypted"] != "false" {
		t.Errorf("a declared-sensitive database is a data node with its posture on it: %+v", r)
	}
	if r := byID["arn:aws:rds:us-east-1:1:db:metrics"]; r.Kind != cloudgraph.KindResource || r.Sensitive != cloudgraph.SensNone || r.Tags["encrypted"] != "true" {
		t.Errorf("an undeclared database is a plain resource: %+v", r)
	}

	runsAs := map[string]string{}
	for _, ra := range inv.RunsAs {
		runsAs[ra.Compute] = ra.Principal
	}
	if runsAs["arn:aws:lambda:us-east-1:1:function:hook"] != "arn:aws:iam::1:role/hook-exec" || runsAs["arn:aws:lambda:us-east-1:1:function:nightly"] != "arn:aws:iam::1:role/nightly-exec" {
		t.Errorf("every function must run as its execution role: %v", runsAs)
	}

	reached := map[string]bool{}
	for _, e := range inv.Reaches {
		if e.From == cloudgraph.InternetID {
			reached[e.To] = true
		}
	}
	if !reached["arn:aws:lambda:us-east-1:1:function:hook"] {
		t.Error("a function URL with no auth is internet-reachable")
	}
	if reached["arn:aws:lambda:us-east-1:1:function:nightly"] {
		t.Error("a function with no public URL is not")
	}
	if !reached["arn:aws:rds:us-east-1:1:db:customers"] {
		t.Error("a public database whose SG opens its port to 0.0.0.0/0 is internet-reachable")
	}
	if reached["arn:aws:rds:us-east-1:1:db:metrics"] {
		t.Error("a public endpoint behind a corp-CIDR SG is NOT internet-reachable — public is not reachability")
	}
	if reached["arn:aws:rds:us-east-1:1:db:noport"] {
		t.Error("an unknown port asserts nothing")
	}
}
