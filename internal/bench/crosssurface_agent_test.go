package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
)

// TestChainDetectorNeedsTheCodeOrigin is the load-bearing guard. The capability under test is
// telling the CROSS-SURFACE story, so reaching the crown is not enough: a cloud-only agent can see
// the customer-PII bucket perfectly well, it just cannot say how anyone on the internet reaches it.
// If naming the crown alone counted, both arms would score the same and the benchmark would measure
// nothing.
func TestChainDetectorNeedsTheCodeOrigin(t *testing.T) {
	fx := LeakedKeyToCloudCrown()

	// Arm-A shape: the agent records the crown but attributes nothing to code.
	cloudOnly := &cloudagent.Report{
		Summary: "deploy-role can read the customer PII bucket; no internet-reachable path found.",
		Issues:  []cloudagent.Issue{{Target: fx.Crown, Rationale: "deploy-role has read access to the bucket"}},
	}
	if reportsCrossSurfaceChain(cloudOnly, fx) {
		t.Error("an agent that named the crown but NOT the code origin scored as telling the\n" +
			"cross-surface story — then both arms score alike and the benchmark measures nothing")
	}

	// Arm-B shape: the agent attributes the entry to the leaked key in the repository.
	estate := &cloudagent.Report{
		Summary: "An AWS key committed to github.com/acme/web/config/deploy.py authenticates as deploy-role, which reads the PII bucket.",
		Issues: []cloudagent.Issue{{Target: fx.Crown,
			Rationale: "the key leaked in config/deploy.py authenticates as deploy-role",
			Evidence:  []string{"gitleaks::aws-access-key"}}},
	}
	if !reportsCrossSurfaceChain(estate, fx) {
		t.Error("an agent that DID attribute the entry to the leaked key in the repo was not credited")
	}
}

// TestChainDetectorRequiresReachingTheCrown pins the other half: talking about the leaked key while
// never recording a path to the crown is not the capability either — that is a code finding, which
// the secret scanner already produced on its own.
func TestChainDetectorRequiresReachingTheCrown(t *testing.T) {
	fx := LeakedKeyToCloudCrown()
	talkOnly := &cloudagent.Report{
		Summary: "A key was committed to github.com/acme/web/config/deploy.py.",
		Issues:  nil, // recorded nothing
	}
	if reportsCrossSurfaceChain(talkOnly, fx) {
		t.Error("mentioning the leaked key without recording a grounded path to the crown scored as\n" +
			"the cross-surface chain — that is just restating the code finding")
	}
}

// TestCrossSurfaceFixtureIsGenuinelyDiscriminating guards the premise of the whole benchmark: the
// cloud account must be a fair one, where a cloud-only answer of "no path" is CORRECT. If the
// substrate could reach the crown from cloud data alone, the two arms would be comparing nothing.
func TestCrossSurfaceFixtureIsGenuinelyDiscriminating(t *testing.T) {
	sc := ScoreCrossSurface(LeakedKeyToCloudCrown())
	if sc.CloudOnlyFoundPath {
		t.Error("the cloud graph alone reaches the crown, so a cloud-only agent is not disadvantaged —\n" +
			"the fixture cannot discriminate and any 'lift' would be an artefact")
	}
	if !sc.EstateFoundPath {
		t.Error("the joined estate cannot reach the crown either, so there is nothing for the agent to\n" +
			"find — an agent failure here would say nothing about the agent")
	}
	if !sc.Lift {
		t.Fatal("substrate lift is the floor this benchmark stands on")
	}
}
