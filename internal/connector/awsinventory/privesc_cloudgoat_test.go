package awsinventory

import (
	"strings"
	"testing"
)

// The CloudGoat-named escalation primitives must reach the PRODUCT graph, not only the bench.
//
// A technique added to the catalogue and proven only through `cloudiam.DetectPrivesc` is the
// built-but-unwired shape this codebase keeps finding: the bench would read 100% while a customer
// posting the same account got no escalation edge. So this drives the real ingest — the policy
// documents exactly as CloudGoat's Terraform grants them — and asserts a privesc edge naming the
// technique comes out the other end.
func TestBuild_CloudGoatPrimitivesProduceAPrivescEdge(t *testing.T) {
	doc := func(actions ...string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["` +
			strings.Join(actions, `","`) + `"],"Resource":"*"}]}`
	}

	cases := []struct {
		name     string
		arn      string
		policy   string
		wantTech string
	}{
		{
			name:     "ecs_privesc_evade_protection",
			arn:      "arn:aws:iam::111122223333:role/cg-web-developer",
			policy:   doc("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:Describe*"),
			wantTech: "PassRoleToNewECSTask",
		},
		{
			name:     "glue_privesc",
			arn:      "arn:aws:iam::111122223333:user/cg-glue-admin",
			policy:   doc("glue:CreateJob", "glue:CreateTrigger", "glue:StartJobRun", "glue:UpdateJob", "iam:PassRole"),
			wantTech: "PassRoleToNewGlueJob",
		},
		{
			name:     "iam_privesc_by_ec2",
			arn:      "arn:aws:iam::111122223333:role/cg-ec2-management",
			policy:   doc("ec2:StartInstances", "ec2:StopInstances", "ec2:ModifyInstanceAttribute"),
			wantTech: "EC2UserDataModification",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := Build(RawAWS{
				AccountID: "111122223333",
				Roles:     []RawIAMRole{{ARN: c.arn, Name: "cg", PoliciesJSON: []string{c.policy}}},
			})
			var got []string
			for _, p := range inv.Privescs {
				if p.Principal != c.arn {
					continue
				}
				got = append(got, p.Detail)
			}
			if len(got) == 0 {
				t.Fatalf("no privesc derived for %s — the technique is in the catalogue but the "+
					"ingest produced no edge, so a customer posting this account sees nothing", c.arn)
			}
			found := false
			for _, g := range got {
				if strings.Contains(g, c.wantTech) {
					found = true
				}
			}
			if !found {
				t.Errorf("want technique %q on the privesc edge, got %v", c.wantTech, got)
			}
		})
	}
}
