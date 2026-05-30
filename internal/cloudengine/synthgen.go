package cloudengine

import (
	"fmt"
	"math/rand"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Synthetic scenario generation (the benchmark Tier 2, docs/design §6). A
// scenario is a (snapshot + live-oracle + ground-truth labels) — no real cloud
// needed, because the engineer reasons over the snapshot. This generator is
// PROCEDURAL + deterministic-from-seed; an LLM "composer" is a pluggable
// enhancement that must still pass the same deterministic Verify() before a
// scenario is admitted (the anti-"grading-your-own-homework" safeguard).

// Scenario is one generated benchmark case with its verified ground truth.
type Scenario struct {
	Snapshot      *cloudgraph.Snapshot
	Prowler       []types.Finding // the L1 "tools say" lens (one per bad resource)
	Blocked       map[string]bool // edge keys blocked at runtime (the live oracle)
	RealTargets   []string        // jewels reachable by a planted real path (must-find)
	DecoyFindings []string        // prowler finding ids that are config-bad but inert (must-downgrade)
}

// Oracle returns the live-oracle Validator for this scenario.
func (s *Scenario) Oracle() Validator { return SnapshotOracle{Blocked: s.Blocked} }

// Generate builds a scenario with nReal planted kill-chains and nDecoy
// config-bad-but-unreachable decoys, deterministically from seed.
func Generate(seed int64, nReal, nDecoy int) *Scenario {
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // benchmark fixture, not crypto
	snap := cloudgraph.New(fmt.Sprintf("acct-%d", seed), "aws")
	snap.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork, Name: "internet"})
	scn := &Scenario{Snapshot: snap, Blocked: map[string]bool{}}

	// Real kill-chains: internet → alb → ec2 → web-role → data-role → PII bucket,
	// every edge unblocked ⇒ reachable.
	for i := 0; i < nReal; i++ {
		alb := id("alb", i)
		ec2 := id("ec2", i)
		web := id("web-role", i)
		data := id("data-role", i)
		bucket := id("pii", i)
		snap.AddNode(&cloudgraph.Node{ID: alb, Kind: cloudgraph.KindResource, Type: "AWS::ELB::LB", Name: alb, Public: true})
		snap.AddNode(&cloudgraph.Node{ID: ec2, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: ec2})
		snap.AddNode(&cloudgraph.Node{ID: web, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: web})
		snap.AddNode(&cloudgraph.Node{ID: data, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: data})
		snap.AddNode(&cloudgraph.Node{ID: bucket, Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: bucket, Sensitive: cloudgraph.SensHigh})
		snap.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: alb, Kind: cloudgraph.EdgeNetworkReach})
		snap.AddEdge(cloudgraph.Edge{From: alb, To: ec2, Kind: cloudgraph.EdgeNetworkReach})
		snap.AddEdge(cloudgraph.Edge{From: ec2, To: web, Kind: cloudgraph.EdgeRunsAs})
		snap.AddEdge(cloudgraph.Edge{From: web, To: data, Kind: cloudgraph.EdgeAssumeRole})
		snap.AddEdge(cloudgraph.Edge{From: data, To: bucket, Kind: cloudgraph.EdgeHasAccess})
		scn.RealTargets = append(scn.RealTargets, bucket)
		// prowler flags the data-role (it has broad S3 access) — corroboratable.
		scn.Prowler = append(scn.Prowler, prowlerFinding(id("f-real", i), "AWS::IAM::Role", data))
	}

	// Decoys: a chain to a sensitive bucket that *looks* exploitable but whose
	// assume edge is blocked by a runtime condition ⇒ config-possible, NOT
	// live-reachable. prowler flags the bucket; the engineer must downgrade it.
	for i := 0; i < nDecoy; i++ {
		alb := id("dalb", i)
		role := id("drole", i)
		priv := id("dpriv", i)
		bucket := id("dpii", i)
		snap.AddNode(&cloudgraph.Node{ID: alb, Kind: cloudgraph.KindResource, Type: "AWS::ELB::LB", Name: alb, Public: true})
		snap.AddNode(&cloudgraph.Node{ID: role, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: role})
		snap.AddNode(&cloudgraph.Node{ID: priv, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: priv})
		snap.AddNode(&cloudgraph.Node{ID: bucket, Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: bucket, Sensitive: cloudgraph.SensHigh})
		snap.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: alb, Kind: cloudgraph.EdgeNetworkReach})
		snap.AddEdge(cloudgraph.Edge{From: alb, To: role, Kind: cloudgraph.EdgeRunsAs})
		blockedEdge := cloudgraph.Edge{From: role, To: priv, Kind: cloudgraph.EdgeAssumeRole, Condition: "aws:MultiFactorAuthPresent=true"}
		snap.AddEdge(blockedEdge)
		snap.AddEdge(cloudgraph.Edge{From: priv, To: bucket, Kind: cloudgraph.EdgeHasAccess})
		scn.Blocked[fmt.Sprintf("%s->%s:%s", role, priv, cloudgraph.EdgeAssumeRole)] = true
		fid := id("f-decoy", i)
		scn.Prowler = append(scn.Prowler, prowlerFinding(fid, "AWS::S3::Bucket", bucket))
		scn.DecoyFindings = append(scn.DecoyFindings, fid)
	}

	// Benign noise so real paths aren't trivially the only resources.
	noise := rng.Intn(5) + 3
	for i := 0; i < noise; i++ {
		n := id("noise", i)
		snap.AddNode(&cloudgraph.Node{ID: n, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: n})
	}
	return scn
}

func id(p string, i int) string { return fmt.Sprintf("%s-%d", p, i) }
func prowlerFinding(fid, typ, name string) types.Finding {
	return types.Finding{
		ID: fid, Tool: "prowler", Severity: types.SeverityHigh,
		Endpoint: fmt.Sprintf("%s %s @us-east-1", typ, name),
	}
}

// Verify is the load-bearing deterministic check: it confirms every planted real
// target IS reachable and every decoy finding's resource is NOT (config-possible
// but blocked). A scenario that fails Verify is malformed and must not be scored
// — this is what defuses the generator↔detector circularity.
func (s *Scenario) Verify() error {
	oracle := s.Oracle()
	// real targets must be reachable from some entry point
	for _, tgt := range s.RealTargets {
		if !s.reachable(tgt, oracle) {
			return fmt.Errorf("verify: planted real target %s is NOT reachable", tgt)
		}
	}
	// decoy resources must be config-possible (a path exists) but NOT reachable
	for _, fid := range s.DecoyFindings {
		res := decoyResource(s, fid)
		possible := s.hasPath(res)
		reach := s.reachable(res, oracle)
		if !possible {
			return fmt.Errorf("verify: decoy %s has no config path (not a decoy)", res)
		}
		if reach {
			return fmt.Errorf("verify: decoy %s IS reachable (not inert)", res)
		}
	}
	return nil
}

func (s *Scenario) hasPath(target string) bool {
	for _, entry := range entryPoints(s.Snapshot) {
		paths := s.Snapshot.FindPaths(entry, func(n *cloudgraph.Node) bool { return n != nil && n.ID == target }, cloudgraph.AllAttackEdges, 8, 5)
		if len(paths) > 0 {
			return true
		}
	}
	return false
}

func (s *Scenario) reachable(target string, oracle Validator) bool {
	for _, entry := range entryPoints(s.Snapshot) {
		paths := s.Snapshot.FindPaths(entry, func(n *cloudgraph.Node) bool { return n != nil && n.ID == target }, cloudgraph.AllAttackEdges, 8, 5)
		for _, p := range paths {
			if ok, _, _ := oracle.Validate(p); ok {
				return true
			}
		}
	}
	return false
}

func decoyResource(s *Scenario, findingID string) string {
	for _, f := range s.Prowler {
		if f.ID == findingID {
			return resourceOf(f)
		}
	}
	return ""
}
