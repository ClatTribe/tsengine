package cloudengine

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Held-out generalization benchmark — the anti-overfit counterpart to the
// in-distribution synthetic bench (synthgen.go).
//
// WHY THIS EXISTS. The in-distribution bench scores ~100% recall / FP-reduction,
// but that number is *circular by construction* and must not be read as a
// capability claim:
//
//   - Its Verify() establishes ground-truth reachability with the SAME FindPaths
//     + SnapshotOracle the engine scores with — the ground truth is defined by
//     the code under test.
//   - Every scenario is one of two hand-authored topologies (one "real", one
//     "decoy"), and every decoy is inert for the SAME single reason (a runtime
//     condition on one edge). The engine is tuned to exactly that.
//
// A 100% there proves the graph/traversal/oracle are internally consistent (a
// good regression signal) — NOT that the engineer generalizes to bad postures it
// was not authored against.
//
// WHAT THIS DOES INSTEAD. It builds a HELD-OUT distribution: bad-posture
// fragments derived from real prowler check ids, whose real/inert ground truth is
// computed by an INDEPENDENT oracle the engine does not run — the full IAM
// effective-permissions evaluator (cloudiam) including permission boundaries, and
// trust-policy evaluation. The graph the engine sees is built the way production
// ingest builds it (over-approximating: an assume edge is traversable regardless
// of the target's trust policy; a privesc edge is added from attached policies
// without consulting the permission boundary). Where the engine's world-model is
// narrower than reality, it reports a path that the independent oracle knows is
// blocked — a false positive. The held-out FP-reduction is the honest overfit
// measure: the gap between "inert shapes the engine encodes" (control) and
// "inert shapes it does not" (probe).
//
// The theme of every held-out class: tsengine ALREADY HAS the evaluator that
// computes the correct answer (cloudiam), but the graph construction does not
// wire it into this reachability dimension — so the gap is precise and fixable,
// not vague.

// postureClass is the independent ground-truth label for a planted posture.
type postureClass int

const (
	classRealReachable postureClass = iota // a genuinely exploitable path (must-find)
	classInertKnown                        // inert for a reason the engine encodes (control: must-downgrade)
	classInertHeldOut                      // inert for a reason the engine does NOT encode (probe: must-downgrade)
)

// plantedPosture is one prowler-check-derived fragment with its independent label.
type plantedPosture struct {
	CheckID    string       // real prowler check id (external diversity source)
	Class      postureClass // independent ground truth
	Reason     string       // why it is real / inert (for the report)
	FindingID  string       // the prowler finding's id
	Resource   string       // the resource the finding is about (join key)
	RealTarget string       // jewel id reached (only meaningful for classRealReachable)
}

// HoldoutScenario is one held-out account with its independently-labelled truth.
type HoldoutScenario struct {
	Snapshot *cloudgraph.Snapshot
	Prowler  []types.Finding
	Planted  []plantedPosture
}

// GenerateHoldout builds a held-out account: K of each posture class, composed
// from prowler-check-derived fragments. Deterministic from seed. The engine-
// visible graph is built with production ingest's over-approximation; the labels
// are computed independently (cloudiam eval incl. boundaries + trust policies).
func GenerateHoldout(seed int64, k int) (*HoldoutScenario, error) {
	if k <= 0 {
		k = 2
	}
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // benchmark fixture, not crypto
	snap := cloudgraph.New(fmt.Sprintf("holdout-%d", seed), "aws")
	snap.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork, Name: "internet"})
	scn := &HoldoutScenario{Snapshot: snap}

	for i := 0; i < k; i++ {
		plantRealReachable(scn, i)
		plantInertIsolated(scn, i)     // control: known inert (no network path)
		plantInertNonSensitive(scn, i) // control: known inert (not a jewel)
		if err := plantHeldOutTrust(scn, i); err != nil {
			return nil, err
		}
		if err := plantHeldOutBoundary(scn, i); err != nil {
			return nil, err
		}
	}

	// benign noise so the real fragments aren't the only resources
	for i := 0; i < rng.Intn(4)+2; i++ {
		n := id("hnoise", i)
		snap.AddNode(&cloudgraph.Node{ID: n, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: n})
	}
	return scn, nil
}

// plantRealReachable: internet → public ALB → EC2 → web-role → data-role → PII.
// Every edge unconditioned ⇒ a genuine, live-reachable kill-chain (must-find).
// prowler check: s3_bucket_level_public_access_block on the exposed data role.
func plantRealReachable(scn *HoldoutScenario, i int) {
	s := scn.Snapshot
	alb, ec2, web, data, pii := id("ralb", i), id("rec2", i), id("rweb", i), id("rdata", i), id("rpii", i)
	s.AddNode(&cloudgraph.Node{ID: alb, Kind: cloudgraph.KindResource, Type: "AWS::ELB::LB", Name: alb, Public: true})
	s.AddNode(&cloudgraph.Node{ID: ec2, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: ec2})
	s.AddNode(&cloudgraph.Node{ID: web, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: web})
	s.AddNode(&cloudgraph.Node{ID: data, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: data})
	s.AddNode(&cloudgraph.Node{ID: pii, Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: pii, Sensitive: cloudgraph.SensHigh})
	s.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: alb, Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: alb, To: ec2, Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: ec2, To: web, Kind: cloudgraph.EdgeRunsAs})
	s.AddEdge(cloudgraph.Edge{From: web, To: data, Kind: cloudgraph.EdgeAssumeRole})
	s.AddEdge(cloudgraph.Edge{From: data, To: pii, Kind: cloudgraph.EdgeHasAccess})
	fid := id("h-real", i)
	scn.Prowler = append(scn.Prowler, prowlerCheck(fid, "s3_bucket_public_access", "AWS::S3::Bucket", pii))
	scn.Planted = append(scn.Planted, plantedPosture{
		CheckID: "s3_bucket_public_access", Class: classRealReachable,
		Reason: "unconditioned internet→…→sensitive chain", FindingID: fid, Resource: pii, RealTarget: pii,
	})
}

// plantInertIsolated: a sensitive bucket prowler flags, but NO entry point
// reaches it. Inert for a reason the engine encodes (FindPaths finds no path →
// correlateProwler downgrades it). Control, not a probe.
func plantInertIsolated(scn *HoldoutScenario, i int) {
	s := scn.Snapshot
	bucket := id("hiso", i)
	s.AddNode(&cloudgraph.Node{ID: bucket, Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: bucket, Sensitive: cloudgraph.SensHigh})
	fid := id("h-iso", i)
	scn.Prowler = append(scn.Prowler, prowlerCheck(fid, "s3_bucket_no_mfa_delete", "AWS::S3::Bucket", bucket))
	scn.Planted = append(scn.Planted, plantedPosture{
		CheckID: "s3_bucket_no_mfa_delete", Class: classInertKnown,
		Reason: "no network path from any entry point", FindingID: fid, Resource: bucket,
	})
}

// plantInertNonSensitive: a public, reachable bucket that holds nothing
// sensitive. prowler flags the public ACL, but it is not a crown jewel, so it is
// not a real-impact path. Inert for a reason the engine encodes (not a jewel).
func plantInertNonSensitive(scn *HoldoutScenario, i int) {
	s := scn.Snapshot
	bucket := id("hpub", i)
	s.AddNode(&cloudgraph.Node{ID: bucket, Kind: cloudgraph.KindResource, Type: "AWS::S3::Bucket", Name: bucket, Public: true})
	s.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: bucket, Kind: cloudgraph.EdgeNetworkReach})
	fid := id("h-pub", i)
	scn.Prowler = append(scn.Prowler, prowlerCheck(fid, "s3_account_level_public_access_blocks", "AWS::S3::Bucket", bucket))
	scn.Planted = append(scn.Planted, plantedPosture{
		CheckID: "s3_account_level_public_access_blocks", Class: classInertKnown,
		Reason: "internet-reachable but holds no sensitive data (not a jewel)", FindingID: fid, Resource: bucket,
	})
}

// plantHeldOutTrust: internet → public ALB → role → [assume] → priv-role →
// sensitive bucket. The engine ingests the assume edge UNCONDITIONED and
// traverses it, reporting a path to the bucket. But priv-role's TRUST policy does
// not name `role` as a permitted principal, so the assumption fails at runtime —
// the path is inert. The independent oracle (cloudiam.Eval over the trust policy)
// proves it. The engine has no trust-policy machinery, so it false-positives.
// prowler check: iam_role_cross_service_confused_deputy_prevention.
func plantHeldOutTrust(scn *HoldoutScenario, i int) error {
	s := scn.Snapshot
	alb, role, priv, bucket := id("htalb", i), id("htrole", i), id("htpriv", i), id("htbucket", i)
	srcArn := "arn:aws:iam::111111111111:role/" + role
	otherArn := "arn:aws:iam::111111111111:role/someone-else"

	// priv-role's trust policy permits ONLY otherArn to assume it — NOT srcArn.
	trust, err := cloudiam.Parse([]byte(fmt.Sprintf(
		`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":%q}]}`, otherArn)))
	if err != nil {
		return fmt.Errorf("holdout trust parse: %w", err)
	}
	// Independent ground truth: can srcArn assume priv-role? (resource = the
	// principal the trust statement is keyed on.) Must be DENY for this to be a
	// valid held-out inert case.
	if allowed, _ := cloudiam.Allows("sts:AssumeRole", srcArn, trust); allowed {
		return fmt.Errorf("holdout trust template %d misconfigured: srcArn IS trusted (not inert)", i)
	}

	s.AddNode(&cloudgraph.Node{ID: alb, Kind: cloudgraph.KindResource, Type: "AWS::ELB::LB", Name: alb, Public: true})
	s.AddNode(&cloudgraph.Node{ID: role, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: role})
	s.AddNode(&cloudgraph.Node{ID: priv, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: priv})
	s.AddNode(&cloudgraph.Node{ID: bucket, Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: bucket, Sensitive: cloudgraph.SensHigh})
	s.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: alb, Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: alb, To: role, Kind: cloudgraph.EdgeRunsAs})
	// over-approximating ingest: the assume edge is added with no trust gate.
	s.AddEdge(cloudgraph.Edge{From: role, To: priv, Kind: cloudgraph.EdgeAssumeRole})
	s.AddEdge(cloudgraph.Edge{From: priv, To: bucket, Kind: cloudgraph.EdgeHasAccess})

	fid := id("h-trust", i)
	scn.Prowler = append(scn.Prowler, prowlerCheck(fid, "iam_role_cross_service_confused_deputy_prevention", "AWS::S3::Bucket", bucket))
	scn.Planted = append(scn.Planted, plantedPosture{
		CheckID: "iam_role_cross_service_confused_deputy_prevention", Class: classInertHeldOut,
		Reason:    "assume_role blocked by target trust policy (engine ignores trust policies)",
		FindingID: fid, Resource: bucket,
	})
	return nil
}

// plantHeldOutBoundary: internet → public ALB → EC2 → role, where role's ATTACHED
// policy enables a privesc technique — but a PERMISSION BOUNDARY denies it. AWS
// effective permission = attached ∧ boundary, so the escalation is blocked. The
// production bridge (AddPrivescEdges) evaluates attached policies only, so it adds
// a spurious privesc→admin edge and the engine reports a false path to admin. The
// independent oracle (attached ∧ boundary) proves it is inert.
// prowler check: iam_policy_no_full_access_to_cloudtrail (privesc-capable policy).
func plantHeldOutBoundary(scn *HoldoutScenario, i int) error {
	s := scn.Snapshot
	alb, ec2, role := id("hbalb", i), id("hbec2", i), id("hbrole", i)

	attached, err := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`))
	if err != nil {
		return fmt.Errorf("holdout boundary attached parse: %w", err)
	}
	// permission boundary: a ceiling that permits only read-only S3 — it does NOT
	// permit iam:CreatePolicyVersion, so the effective permission is denied.
	boundary, err := cloudiam.Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"}]}`))
	if err != nil {
		return fmt.Errorf("holdout boundary parse: %w", err)
	}
	// Independent ground truth: effective = allowed by attached AND by boundary.
	attAllow, _ := cloudiam.Allows("iam:CreatePolicyVersion", "*", attached)
	bndAllow, _ := cloudiam.Allows("iam:CreatePolicyVersion", "*", boundary)
	if attAllow && bndAllow {
		return fmt.Errorf("holdout boundary template %d misconfigured: boundary does not block (not inert)", i)
	}

	s.AddNode(&cloudgraph.Node{ID: alb, Kind: cloudgraph.KindResource, Type: "AWS::ELB::LB", Name: alb, Public: true})
	s.AddNode(&cloudgraph.Node{ID: ec2, Kind: cloudgraph.KindResource, Type: "AWS::EC2::Instance", Name: ec2})
	s.AddNode(&cloudgraph.Node{ID: role, Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: role})
	s.AddEdge(cloudgraph.Edge{From: cloudgraph.InternetID, To: alb, Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: alb, To: ec2, Kind: cloudgraph.EdgeNetworkReach})
	s.AddEdge(cloudgraph.Edge{From: ec2, To: role, Kind: cloudgraph.EdgeRunsAs})
	// over-approximating ingest: privesc edge from ATTACHED policy only (the bug).
	s.AddPrivescEdges(map[string][]*cloudiam.Document{role: {attached}})

	fid := id("h-bound", i)
	scn.Prowler = append(scn.Prowler, prowlerCheck(fid, "iam_inline_policy_allows_privilege_escalation", "AWS::IAM::Role", role))
	scn.Planted = append(scn.Planted, plantedPosture{
		CheckID: "iam_inline_policy_allows_privilege_escalation", Class: classInertHeldOut,
		Reason:    "privesc blocked by permission boundary (engine ignores boundaries)",
		FindingID: fid, Resource: role,
	})
	return nil
}

// prowlerCheck builds a prowler-style finding carrying the real check id. The
// Endpoint "<type> <name> @<region>" matches the prowler parser so resourceOf()
// joins on the resource name.
func prowlerCheck(fid, checkID, typ, name string) types.Finding {
	return types.Finding{
		ID: fid, RuleID: "prowler::" + checkID, Tool: "prowler", Severity: types.SeverityHigh,
		Title:    checkID,
		Endpoint: fmt.Sprintf("%s %s @us-east-1", typ, name),
	}
}

// HoldoutScore splits accuracy by in-distribution control vs held-out probe. The
// HELD-OUT FP-reduction (and the gap below the control) is the overfit measure.
type HoldoutScore struct {
	RealTotal     int      `json:"real_total"`
	RealFound     int      `json:"real_found"`
	PathRecall    float64  `json:"path_recall"`
	KnownTotal    int      `json:"known_inert_total"`
	KnownDown     int      `json:"known_inert_downgraded"`
	KnownFPRed    float64  `json:"known_fp_reduction"`
	HeldOutTotal  int      `json:"held_out_inert_total"`
	HeldOutDown   int      `json:"held_out_inert_downgraded"`
	HeldOutFPRed  float64  `json:"held_out_fp_reduction"`
	FalsePaths    int      `json:"false_paths"`
	Pass          bool     `json:"pass"`
	HeldOutMissed []string `json:"held_out_missed,omitempty"` // check ids the engine false-positived
}

// ScoreHoldout compares the engine's assessment against the independent labels.
func ScoreHoldout(scn *HoldoutScenario, a *types.AIAssessment) HoldoutScore {
	realTargets := map[string]bool{}
	for _, p := range scn.Planted {
		if p.Class == classRealReachable {
			realTargets[p.RealTarget] = true
		}
	}
	downgraded := map[string]bool{}
	for _, d := range a.Downgraded {
		downgraded[d] = true
	}
	foundTarget := map[string]bool{}
	falsePaths := 0
	for _, path := range a.Paths {
		end := pathEnd(path)
		if realTargets[end] {
			foundTarget[end] = true
		} else {
			falsePaths++
		}
	}

	var s HoldoutScore
	var missed []string
	for _, p := range scn.Planted {
		switch p.Class {
		case classRealReachable:
			s.RealTotal++
			if foundTarget[p.RealTarget] {
				s.RealFound++
			}
		case classInertKnown:
			s.KnownTotal++
			if downgraded[p.FindingID] {
				s.KnownDown++
			}
		case classInertHeldOut:
			s.HeldOutTotal++
			if downgraded[p.FindingID] {
				s.HeldOutDown++
			} else {
				missed = appendUnique(missed, p.CheckID)
			}
		}
	}
	s.PathRecall = ratio(s.RealFound, s.RealTotal)
	s.KnownFPRed = ratio(s.KnownDown, s.KnownTotal)
	s.HeldOutFPRed = ratio(s.HeldOutDown, s.HeldOutTotal)
	s.FalsePaths = falsePaths
	sort.Strings(missed)
	s.HeldOutMissed = missed
	s.Pass = s.RealFound == s.RealTotal && s.KnownDown == s.KnownTotal &&
		s.HeldOutDown == s.HeldOutTotal && s.FalsePaths == 0
	return s
}

// RunHoldout generates → assesses → scores n held-out accounts and aggregates.
func RunHoldout(seedBase int64, n, k, maxHyp int) (HoldoutScore, int, error) {
	agg := HoldoutScore{Pass: true}
	missed := map[string]bool{}
	for i := 0; i < n; i++ {
		scn, err := GenerateHoldout(seedBase+int64(i), k)
		if err != nil {
			return agg, i, fmt.Errorf("holdout %d: %w", i, err)
		}
		a := Assess(scn.Snapshot, scn.Prowler, SnapshotOracle{}, Options{MaxHypotheses: maxHyp})
		s := ScoreHoldout(scn, a)
		agg.RealTotal += s.RealTotal
		agg.RealFound += s.RealFound
		agg.KnownTotal += s.KnownTotal
		agg.KnownDown += s.KnownDown
		agg.HeldOutTotal += s.HeldOutTotal
		agg.HeldOutDown += s.HeldOutDown
		agg.FalsePaths += s.FalsePaths
		for _, m := range s.HeldOutMissed {
			missed[m] = true
		}
		if !s.Pass {
			agg.Pass = false
		}
	}
	agg.PathRecall = ratio(agg.RealFound, agg.RealTotal)
	agg.KnownFPRed = ratio(agg.KnownDown, agg.KnownTotal)
	agg.HeldOutFPRed = ratio(agg.HeldOutDown, agg.HeldOutTotal)
	for m := range missed {
		agg.HeldOutMissed = append(agg.HeldOutMissed, m)
	}
	sort.Strings(agg.HeldOutMissed)
	return agg, n, nil
}

// RenderHoldout formats the held-out scorecard with the honest overfit framing.
func RenderHoldout(agg HoldoutScore, n int) string {
	var b strings.Builder
	verdict := "PASS"
	if !agg.Pass {
		verdict = "FAIL (held-out gap — see below)"
	}
	gap := agg.KnownFPRed - agg.HeldOutFPRed
	fmt.Fprintf(&b, "=== AI Cloud Engineer — HELD-OUT generalization (%d accounts) ===\n", n)
	fmt.Fprintf(&b, "attack-path recall:        %.2f%%  (%d/%d genuinely-reachable paths)\n",
		agg.PathRecall*100, agg.RealFound, agg.RealTotal)
	fmt.Fprintf(&b, "FP-reduction (known shapes):   %.2f%%  (%d/%d)  ← in-distribution control\n",
		agg.KnownFPRed*100, agg.KnownDown, agg.KnownTotal)
	fmt.Fprintf(&b, "FP-reduction (HELD-OUT shapes): %.2f%%  (%d/%d)  ← the generalization probe\n",
		agg.HeldOutFPRed*100, agg.HeldOutDown, agg.HeldOutTotal)
	fmt.Fprintf(&b, "overfit gap (control − held-out): %.1f points\n", gap*100)
	fmt.Fprintf(&b, "false attack paths:        %d\n", agg.FalsePaths)
	fmt.Fprintf(&b, "verdict:                   %s\n", verdict)
	if len(agg.HeldOutMissed) > 0 {
		fmt.Fprintf(&b, "false-positived prowler checks (engine reported a blocked path as real):\n")
		for _, m := range agg.HeldOutMissed {
			fmt.Fprintf(&b, "  - %s\n", m)
		}
	}
	fmt.Fprintf(&b, "interpretation: the in-distribution synthetic bench scores ~100%% because its\n")
	fmt.Fprintf(&b, "  ground truth is defined by the same oracle the engine scores with. This\n")
	fmt.Fprintf(&b, "  held-out set labels truth INDEPENDENTLY (cloudiam eval incl. permission\n")
	fmt.Fprintf(&b, "  boundaries + trust policies). The held-out gap is real coverage the engine\n")
	fmt.Fprintf(&b, "  lacks: graph ingest over-approximates reachability (assume edges ignore\n")
	fmt.Fprintf(&b, "  trust policies; privesc edges ignore permission boundaries). tsengine HAS\n")
	fmt.Fprintf(&b, "  the evaluator (cloudiam) to close this — the fix is wiring it into ingest.\n")
	return b.String()
}
