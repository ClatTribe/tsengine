package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// The benchmark's headline: the join finds an attack path the cloud account alone cannot.
func TestCrossSurface_JoinFindsWhatCloudAloneCannot(t *testing.T) {
	sc := ScoreCrossSurface(LeakedKeyToCloudCrown())

	// The cloud-alone miss is the load-bearing half of the measurement. If a future change makes
	// the cloud graph find this path on its own, the fixture has stopped being a two-surface test
	// and the "lift" number would be measuring nothing — so this failing is a real signal, not a
	// nuisance assertion to relax.
	if sc.CloudOnlyFoundPath {
		t.Fatalf("fixture no longer isolates the surfaces: the cloud graph alone reached the crown, " +
			"so any 'lift' this reports would be an artefact")
	}
	if !sc.EstateFoundPath {
		t.Fatalf("the joined estate did not reach the crown — the traversal the whole capability rests on")
	}
	if !sc.Lift {
		t.Fatalf("no lift measured: cloud=%v estate=%v", sc.CloudOnlyFoundPath, sc.EstateFoundPath)
	}
	if len(sc.EstateFindings) == 0 {
		t.Errorf("the join reached the crown but produced no cross-surface finding — a path nobody is told about")
	}
	t.Logf("cross-surface lift confirmed: cloud-alone=not-found, estate=found, detections=%v", sc.EstateFindings)
	t.Logf("\n%s", RenderCrossSurface(sc))
}

// A benchmark that only ever reports a lift is a benchmark that cannot fail. Give the same scorer a
// fixture where the cloud account ALREADY exposes the crown, and it must report no lift — the join
// did not add the finding, the cloud scanner had it.
func TestCrossSurface_NoLiftWhenCloudAlreadySeesIt(t *testing.T) {
	fx := LeakedKeyToCloudCrown()
	inv := cloudgraph.Inventory{
		Provider: "aws", AccountID: "000000000000",
		Resources: []cloudgraph.InvResource{
			{ID: "i-public", Kind: "compute", Name: "public-web", Public: true},
			{ID: "arn:aws:s3:::acme-customer-pii", Kind: "data", Name: "acme-customer-pii", Sensitive: cloudgraph.SensHigh},
		},
		// This time the account itself has the way in: an internet-facing instance that can read it.
		Reaches: []cloudgraph.InvReach{{From: cloudgraph.InternetID, To: "i-public"}},
		Grants:  []cloudgraph.InvGrant{{Principal: "i-public", Resource: "arn:aws:s3:::acme-customer-pii"}},
	}
	fx.Cloud = cloudgraph.Ingest(inv)

	sc := ScoreCrossSurface(fx)
	if !sc.CloudOnlyFoundPath {
		t.Fatalf("control fixture is wrong: the cloud graph should see its own internet→crown path")
	}
	if sc.Lift {
		t.Errorf("[OVERCLAIM] reported a cross-surface lift for a path the cloud scanner already found")
	}
	if strings.Contains(RenderCrossSurface(sc), "**LIFT: yes**") {
		t.Errorf("the scorecard claims a lift the score does not support")
	}
}

// The second join, asking a different question: what does the pentest target reach? The cloud graph
// cannot answer it at all — a hostname is not an identifier a cloud account holds — so the lift here
// is not a longer path but a question becoming answerable.
func TestCrossSurface_WebHostJoinAnswersWhatTheTargetReaches(t *testing.T) {
	sc := ScoreCrossSurface(WebHostToCloudCrown())

	if sc.CloudOnlyFoundPath {
		t.Fatalf("the cloud graph reported a path from a hostname it does not hold as a node — " +
			"the fixture no longer isolates the surfaces")
	}
	if !sc.EstateFoundPath {
		t.Fatalf("the joined estate could not trace the pentest target to the crown it reaches; " +
			"the AI pentester would prioritise this route no differently from a marketing page")
	}
	if !sc.Lift {
		t.Fatalf("no lift measured: cloud=%v estate=%v", sc.CloudOnlyFoundPath, sc.EstateFoundPath)
	}
	t.Logf("\n%s", RenderCrossSurface(sc))
}

// The refusal that makes the web join trustworthy. Given the SAME account with the DNS name removed,
// nothing may join the hostname to the resource on the strength of a similar-looking name — a wrong
// join fabricates an attack path, which is worse than two disconnected subgraphs.
func TestCrossSurface_WebHostNotJoinedWithoutTheInventorySayingSo(t *testing.T) {
	fx := WebHostToCloudCrown()
	inv := cloudgraph.Inventory{
		Provider: "aws", AccountID: "000000000000",
		Resources: []cloudgraph.InvResource{
			// Same box, same app, named after the host — but no DNS name asserted.
			{ID: "i-web", Kind: "resource", Type: "ec2_instance", Name: "app.example.com", Public: true},
			{ID: "arn:aws:s3:::acme-customer-pii", Kind: "data", Sensitive: cloudgraph.SensHigh},
		},
		Grants: []cloudgraph.InvGrant{{Principal: "i-web", Resource: "arn:aws:s3:::acme-customer-pii"}},
	}
	fx.Cloud = cloudgraph.Ingest(inv)

	sc := ScoreCrossSurface(fx)
	if sc.EstateFoundPath {
		t.Errorf("[FABRICATED] joined a hostname to a resource the inventory never said it was")
	}
	if sc.Lift {
		t.Errorf("[OVERCLAIM] reported a lift built on an unasserted identity")
	}
}
