package awsinventory

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestCIEM_PostedInventoryEndToEnd proves the live posted-inventory path: a RawAWS role carrying
// entitlement (granted iam:*, observed usage = nothing) → Build → Ingest → RightsizePrincipals produces
// a high over-privilege finding. This is CIEM working end-to-end for the credential-free posted-snapshot
// path, not just the core.
func TestCIEM_PostedInventoryEndToEnd(t *testing.T) {
	raw := RawAWS{
		AccountID: "111122223333",
		Roles: []RawIAMRole{{
			ARN: "arn:aws:iam::111122223333:role/legacy-deploy", Name: "legacy-deploy", Admin: true,
			Entitlement: &cloudgraph.Entitlement{
				GrantedActions: []string{"iam:*", "s3:GetObject", "ec2:*"},
				UsedActions:    []string{"s3:GetObject"}, // used only S3 read; iam:* / ec2:* dormant
				WindowDays:     90,
				Observed:       true,
			},
		}},
	}
	snap := cloudgraph.Ingest(Build(raw))
	fs := cloudengine.RightsizePrincipals(snap)
	if len(fs) != 1 {
		t.Fatalf("want 1 CIEM finding from the posted inventory, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != types.SeverityHigh {
		t.Errorf("a dormant admin (iam:* unused) must be high, got %s", f.Severity)
	}
	if f.Endpoint != "arn:aws:iam::111122223333:role/legacy-deploy" {
		t.Errorf("endpoint should be the role ARN, got %s", f.Endpoint)
	}

	// control: the SAME inventory without entitlement data yields NO CIEM finding (honest gate §10).
	rawNoUsage := RawAWS{AccountID: "111122223333", Roles: []RawIAMRole{{ARN: "arn:aws:iam::111122223333:role/legacy-deploy", Admin: true}}}
	if fs := cloudengine.RightsizePrincipals(cloudgraph.Ingest(Build(rawNoUsage))); len(fs) != 0 {
		t.Errorf("no entitlement data → no CIEM finding, got %d", len(fs))
	}
}
