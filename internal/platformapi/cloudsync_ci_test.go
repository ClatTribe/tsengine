package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The live sync path (the one a connected customer actually uses) must run the same CI/federated-
// identity assessment as the posted-inventory path. Before this it did not: a role assumable by ANY
// GitHub repository produced a finding when its trust policy was POSTED and nothing when it was
// READ through the connected role — and the posted path is the one no customer uses once they have
// connected. Mutation check: reverting cloudsync.go's ciIdentityAssess call makes this fail.

type fetchIAM struct{ out []awsfetch.Principal }

func (f fetchIAM) ListPrincipals(context.Context) ([]awsfetch.Principal, error) { return f.out, nil }

const anyRepoTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}]}`

func TestCloudSync_LivePathRunsTheCIIdentityAssessment(t *testing.T) {
	d := syncDeps(t, fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}}, true)
	d.AWSFetcher = func(c platform.Connection) awsfetch.Fetcher {
		return awsfetch.Fetcher{
			AccountID: c.Account,
			Buckets:   fetchLister{out: []awsfetch.Bucket{{Name: "logs"}}},
			Principals: fetchIAM{out: []awsfetch.Principal{{
				ARN: "arn:aws:iam::123456789012:role/Deploy", Name: "Deploy", Role: true, Admin: true, Trust: anyRepoTrust,
			}}},
		}
	}

	if _, _, err := d.SyncCloudInventory(context.Background(), "ten-1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	fs, err := d.Store.ListFindings(context.Background(), "ten-1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var ci []string
	for _, f := range fs {
		if strings.HasPrefix(f.RuleID, "ghoidc::") {
			ci = append(ci, f.RuleID+" "+f.Endpoint)
		}
	}
	if len(ci) == 0 {
		t.Fatalf("the live sync stored no ghoidc finding for an admin role any GitHub repository can assume; findings: %d", len(fs))
	}
	if !strings.Contains(strings.Join(ci, "\n"), "role/Deploy") {
		t.Errorf("the finding must name the role: %v", ci)
	}

	// The coverage the live read could not answer is STORED with the snapshot, as the posted path does.
	snap, ok, err := d.CloudSnapshots.Get(context.Background(), "ten-1")
	if err != nil || !ok {
		t.Fatalf("snapshot not stored: ok=%v err=%v", ok, err)
	}
	if len(snap.CoverageGaps) == 0 {
		t.Error("the live sync stored no coverage notes — a partial read renders as a whole one on the attack-path page")
	}
}
