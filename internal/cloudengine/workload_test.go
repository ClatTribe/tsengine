package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

func workloadSnap() *cloudgraph.Snapshot {
	s := &cloudgraph.Snapshot{AccountID: "111122223333", Provider: "aws", Nodes: map[string]*cloudgraph.Node{}}
	// A public ECS task running image A.
	s.AddNode(&cloudgraph.Node{ID: "ecs-public", Kind: cloudgraph.KindResource, Type: "AWS::ECS::TaskDefinition",
		Name: "api", Region: "us-east-1", Public: true, Attrs: map[string]string{"image": "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:1.2"}})
	// An internal EKS pod also running image A (same image → one scan, two nodes).
	s.AddNode(&cloudgraph.Node{ID: "eks-internal", Kind: cloudgraph.KindResource, Type: "AWS::EKS::Pod",
		Name: "worker", Attrs: map[string]string{"image": "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:1.2"}})
	// A public Lambda (image package) running image B.
	s.AddNode(&cloudgraph.Node{ID: "lambda-public", Kind: cloudgraph.KindResource, Type: "AWS::Lambda::Function",
		Name: "thumb", Public: true, Attrs: map[string]string{"image": "111122223333.dkr.ecr.us-east-1.amazonaws.com/thumb:3"}})
	// A node with no image (a bucket) → not a workload.
	s.AddNode(&cloudgraph.Node{ID: "bucket", Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket"})
	return s
}

func TestWorkloadScanPlan_DedupAndExtract(t *testing.T) {
	plan := WorkloadScanPlan(workloadSnap())
	if len(plan) != 2 {
		t.Fatalf("want 2 unique images to scan, got %d: %+v", len(plan), plan)
	}
	// Image A is referenced by both ECS + EKS → one scan entry, two nodes.
	var imgA *WorkloadImage
	for i := range plan {
		if plan[i].Image == "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:1.2" {
			imgA = &plan[i]
		}
	}
	if imgA == nil {
		t.Fatal("image A should be in the plan")
	}
	if len(imgA.Nodes) != 2 {
		t.Errorf("image A runs on 2 nodes (ECS+EKS), got %v", imgA.Nodes)
	}
	if imgA.ComputeType == "" {
		t.Error("compute type should be derived from the node type")
	}
}

func TestWorkloadExposures_ToxicCombo(t *testing.T) {
	snap := workloadSnap()
	vulns := []WorkloadVuln{
		{Image: "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:1.2", Critical: 2, High: 5, TopCVE: "CVE-2024-3094"},
		{Image: "111122223333.dkr.ecr.us-east-1.amazonaws.com/thumb:3", High: 0, Critical: 0}, // clean
	}
	exp := WorkloadExposures(snap, vulns, nil)

	// Only the PUBLIC node running the VULNERABLE image is a toxic combo. The internal EKS
	// pod (same vulnerable image, but not internet-reachable) is NOT emitted here; the clean
	// public Lambda is NOT emitted (no vulns).
	if len(exp) != 1 {
		t.Fatalf("want exactly 1 toxic-combo exposure, got %d: %+v", len(exp), exp)
	}
	if !affects(exp[0].Affected, "ecs-public") {
		t.Errorf("the public vulnerable workload should be the exposure, got %v", exp[0].Affected)
	}
	if exp[0].RealImpact.LiveReachable != true {
		t.Error("an internet-reachable workload exposure should be live-reachable")
	}
	if exp[0].Compliance == nil {
		t.Error("an internet-exposed workload should map to compliance controls")
	}
	if exp[0].Narrative == "" {
		t.Error("needs a plain-English toxic-combo narrative")
	}
}

func TestWorkloadExposures_GroundingAndDedup(t *testing.T) {
	snap := workloadSnap()
	vulns := []WorkloadVuln{{Image: "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:1.2", Critical: 1}}

	// No vulns at all → nothing.
	if e := WorkloadExposures(snap, nil, nil); len(e) != 0 {
		t.Errorf("no scan results → no exposures, got %d", len(e))
	}
	// Covered (already on a discovered path) → deduped out.
	if e := WorkloadExposures(snap, vulns, map[string]bool{"ecs-public": true}); len(e) != 0 {
		t.Errorf("a workload already covered by a path must be deduped out, got %d", len(e))
	}
	// A clean image (no critical/high) on a public node → not a finding (grounded).
	clean := []WorkloadVuln{{Image: "111122223333.dkr.ecr.us-east-1.amazonaws.com/thumb:3", Critical: 0, High: 0}}
	if e := WorkloadExposures(snap, clean, nil); len(e) != 0 {
		t.Errorf("a clean workload image must not produce an exposure, got %d", len(e))
	}
}
