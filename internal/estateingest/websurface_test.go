package estateingest

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// THE CHAIN THE PENTESTER NEEDS: a hostname it is pointed at must lead, through the cloud account,
// to something worth taking — otherwise every route looks the same and the agent spends its request
// budget on the shape of a URL rather than on the stakes behind it.
func TestWebSurface_HostnameLeadsToACrownJewel(t *testing.T) {
	g := FromCloud(cloudgraph.Ingest(cloudgraph.Inventory{
		Provider: "aws", AccountID: "111122223333",
		Resources: []cloudgraph.InvResource{
			{ID: "i-web", Kind: cloudgraph.KindResource, Type: "ec2_instance", Public: true,
				DNSNames: []string{"app.example.com"}},
			{ID: "arn:aws:iam::111122223333:role/app", Kind: cloudgraph.KindPrincipal, Name: "app-role"},
			{ID: "arn:aws:s3:::customer-pii", Kind: cloudgraph.KindData, Name: "customer-pii",
				Sensitive: cloudgraph.SensHigh},
		},
		RunsAs: []cloudgraph.InvRunsAs{{Compute: "i-web", Principal: "arn:aws:iam::111122223333:role/app"}},
		Grants: []cloudgraph.InvGrant{{Principal: "arn:aws:iam::111122223333:role/app",
			Resource: "arn:aws:s3:::customer-pii"}},
	}))

	leads := LeadsForRoutes(g, []string{"https://app.example.com"})
	if len(leads) == 0 {
		t.Fatalf("the pentester's target reaches a PII bucket through the account and got NO lead — " +
			"the agent would prioritise this route no differently from a marketing page")
	}
	if leads[0].Reaches == "" || leads[0].Why == "" {
		t.Errorf("a lead with no stakes and no chain tells the agent nothing: %+v", leads[0])
	}
	if len(leads[0].Evidence) == 0 {
		t.Errorf("a lead citing no evidence cannot be checked: %+v", leads[0])
	}
	t.Logf("lead: %s reaches %s — %s", leads[0].Route, leads[0].Reaches, leads[0].Why)
}

// The refusal that makes the join trustworthy: a hostname the inventory never asserted must NOT be
// joined to a resource just because it looks related. A wrong join fabricates an attack path, which
// is worse than two disconnected subgraphs.
func TestWebSurface_UnassertedHostnameIsNotJoined(t *testing.T) {
	g := FromCloud(cloudgraph.Ingest(cloudgraph.Inventory{
		Provider: "aws", AccountID: "111122223333",
		Resources: []cloudgraph.InvResource{
			// Same account, same app, no DNS name recorded.
			{ID: "i-web", Kind: cloudgraph.KindResource, Type: "ec2_instance", Name: "app.example.com", Public: true},
			{ID: "arn:aws:s3:::customer-pii", Kind: cloudgraph.KindData, Sensitive: cloudgraph.SensHigh},
		},
		Grants: []cloudgraph.InvGrant{{Principal: "i-web", Resource: "arn:aws:s3:::customer-pii"}},
	}))

	if id := estategraph.Canonical(SurfaceWeb, "https://app.example.com"); g.Nodes[id] != nil {
		t.Errorf("a hostname was joined from a resource NAME that merely resembles it — exactly the " +
			"fuzzy identity resolution the graph refuses")
	}
	if leads := LeadsForRoutes(g, []string{"https://app.example.com"}); len(leads) != 0 {
		t.Errorf("produced %d lead(s) for a hostname nothing asserted: %+v", len(leads), leads)
	}
}
