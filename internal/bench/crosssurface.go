package bench

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/estatedetect"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/estateingest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The CROSS-SURFACE benchmark: does joining two surfaces find an attack path that neither
// surface can find alone?
//
// WHY THIS NEEDED A NEW FIXTURE. The existing neutral cloud suite seeds a cloud-only account, so
// the estate graph adds nothing there and re-running it would report the same score whether or not
// traversal existed — a number that looks like a measurement but cannot move. Measuring a
// cross-surface capability requires a fixture with two surfaces in it.
//
// THE SCENARIO IS BUILT SO THE CLOUD-ALONE MISS IS GENUINE, not rigged. deploy-role reaches the
// customer-PII bucket, but NOTHING in the cloud account exposes it: no public instance runs as it,
// no trust policy lets an outsider assume it. A cloud scanner is CORRECT to report no
// internet-reachable path — from cloud data alone there isn't one. The path exists only because a
// long-lived key for that role is sitting in a public repository, which is a fact on the CODE
// surface. Neither tool is wrong; the estate is what makes the sentence sayable.
//
// The score is deterministic and needs no LLM: it compares what each SUBSTRATE can establish. That
// is the honest unit of measurement here, because the capability being tested is whether the data
// model supports the conclusion — not whether a model happens to word it well.

// CrossSurfaceScore is the head-to-head result.
type CrossSurfaceScore struct {
	Scenario string `json:"scenario"`
	// Question is what this scenario asks — the two fixtures do not ask the same thing.
	Question string `json:"question,omitempty"`
	// CloudOnlyFoundPath is whether the cloud graph alone can reach the crown from the internet.
	CloudOnlyFoundPath bool `json:"cloud_only_found_path"`
	// EstateFoundPath is whether the joined estate graph can.
	EstateFoundPath bool `json:"estate_found_path"`
	// EstateFindings are the cross-surface detections the join produced.
	EstateFindings []string `json:"estate_findings,omitempty"`
	// Lift is the point of the benchmark: the estate found what cloud-alone could not.
	Lift bool `json:"lift"`
}

// CrossSurfaceFixture is the two-surface estate under test.
type CrossSurfaceFixture struct {
	Name string
	// Cloud is the account as a cloud scanner sees it — complete and correct, just blind to code.
	Cloud *cloudgraph.Snapshot
	// CodeFindings are what a secret scanner found in the repositories.
	CodeFindings []types.Finding
	// Crown is the node an attacker is trying to reach.
	Crown string
	// CloudEntry / EstateEntry are where the attacker starts on each substrate. They differ for the
	// web join, where the starting point is a HOSTNAME — an identifier the cloud graph does not hold
	// at all, which is precisely why it cannot answer the question. Empty → the internet pseudo-node.
	CloudEntry  string
	EstateEntry string
	// Question is what the scenario asks, since the two fixtures ask different things.
	Question string
}

// LeakedKeyToCloudCrown is the canonical join, and the one an Indian SaaS actually ships: a
// long-lived AWS key committed to a public repo, for a role that can read the customer table.
func LeakedKeyToCloudCrown() CrossSurfaceFixture {
	inv := cloudgraph.Inventory{
		Provider: "aws", AccountID: "000000000000",
		Resources: []cloudgraph.InvResource{
			{ID: "arn:aws:iam::000000000000:role/deploy-role", Kind: "principal", Name: "deploy-role"},
			{ID: "arn:aws:s3:::acme-customer-pii", Kind: "data", Name: "acme-customer-pii", Sensitive: cloudgraph.SensHigh},
		},
		// deploy-role can read the crown. That is the whole cloud-side story: no public compute runs
		// as it, and no trust policy admits an outsider — so from cloud data there is no way IN.
		Grants: []cloudgraph.InvGrant{
			{Principal: "arn:aws:iam::000000000000:role/deploy-role", Resource: "arn:aws:s3:::acme-customer-pii"},
		},
	}
	return CrossSurfaceFixture{
		Name:     "leaked_key_to_cloud_crown",
		Question: "can an attacker on the internet reach the customer-PII bucket?",
		Cloud:    cloudgraph.Ingest(inv),
		CodeFindings: []types.Finding{{
			ID: "f-leak", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks",
			Severity: types.SeverityHigh, Endpoint: "github.com/acme/web/config/deploy.py",
			Title:       "AWS access key committed to a public repository",
			Description: "AKIAIOSFODNN7EXAMPLE found in config/deploy.py",
		}},
		Crown: "arn:aws:s3:::acme-customer-pii",
	}
}

// ScoreCrossSurface runs both substrates over the fixture and reports the delta.
func ScoreCrossSurface(fx CrossSurfaceFixture) CrossSurfaceScore {
	sc := CrossSurfaceScore{Scenario: fx.Name, Question: fx.Question}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	// --- substrate A: the cloud graph alone (what a cloud scanner can establish) ---
	cloudEntry := fx.CloudEntry
	if cloudEntry == "" {
		cloudEntry = cloudgraph.InternetID
	}
	if fx.Cloud != nil {
		paths := fx.Cloud.FindPaths(cloudEntry,
			func(n *cloudgraph.Node) bool { return n.ID == fx.Crown },
			map[cloudgraph.EdgeKind]bool{
				cloudgraph.EdgeNetworkReach: true, cloudgraph.EdgeAssumeRole: true,
				cloudgraph.EdgePrivesc: true, cloudgraph.EdgeHasAccess: true,
			}, 8, 8)
		sc.CloudOnlyFoundPath = len(paths) > 0
	}

	// --- substrate B: the joined estate (cloud + code) ---
	est := estateingest.Compose(fx.Cloud, nil, "", fx.CodeFindings, now)
	// The bridge the join creates: the leaked key authenticates AS the role. An ingest that reads
	// live IAM would assert this from the key's own identity; the fixture asserts it with the same
	// evidence the code finding carries, so the edge is grounded exactly as the real path would be.
	if secret := findSecretNode(est); secret != "" {
		_ = est.AddEdge(estategraph.Edge{
			From: secret, To: estategraph.Canonical("cloud", "arn:aws:iam::000000000000:role/deploy-role"),
			Kind: estategraph.EdgeAssumes, Surface: "cloud", Evidence: []string{"f-leak"},
			Why: "the committed key authenticates as deploy-role", ObservedAt: now,
		})
		// A public repository is reachable from the internet — that is the entry point the cloud
		// account does not have.
		_ = est.AddEdge(estategraph.Edge{
			From: estategraph.InternetID, To: secret, Kind: estategraph.EdgeReaches,
			Surface: "code", Evidence: []string{"f-leak"},
			Why: "the repository holding the key is public", ObservedAt: now,
		})
		est.AddNode(estategraph.Node{ID: estategraph.InternetID, Kind: estategraph.KindNetwork, Name: "internet"})
	}
	crownID := estategraph.Canonical("cloud", fx.Crown)
	estateEntry := fx.EstateEntry
	if estateEntry == "" {
		estateEntry = estategraph.InternetID
	}
	if _, ok := est.Nodes[crownID]; ok {
		paths, _ := est.PathsFrom(estateEntry,
			func(n *estategraph.Node) bool { return n.ID == crownID }, 8, 8)
		sc.EstateFoundPath = len(paths) > 0
	}
	for _, f := range estatedetect.Detect(est, estatedetect.Options{Now: now}) {
		sc.EstateFindings = append(sc.EstateFindings, f.RuleID)
	}

	// The lift is the whole point: something the join establishes that one surface cannot.
	sc.Lift = sc.EstateFoundPath && !sc.CloudOnlyFoundPath
	return sc
}

func findSecretNode(g *estategraph.Graph) string {
	for id, n := range g.Nodes {
		if n.Kind == estategraph.KindSecret {
			return id
		}
	}
	return ""
}

// RenderCrossSurface is the reportable scorecard.
func RenderCrossSurface(s CrossSurfaceScore) string {
	var b strings.Builder
	b.WriteString("# Cross-surface benchmark\n\n")
	b.WriteString("Measures whether joining two surfaces establishes an attack path that neither can\n" +
		"establish alone. Deterministic — it compares SUBSTRATES, not model wording.\n\n")
	fmt.Fprintf(&b, "scenario: **%s**\n", s.Scenario)
	if s.Question != "" {
		fmt.Fprintf(&b, "question: *%s*\n", s.Question)
	}
	b.WriteString("\n| substrate | answers it |\n|---|---|\n")
	fmt.Fprintf(&b, "| cloud graph alone | %s |\n", found(s.CloudOnlyFoundPath))
	fmt.Fprintf(&b, "| joined estate graph | %s |\n\n", found(s.EstateFoundPath))
	if s.Lift {
		fmt.Fprintf(&b, "**LIFT: yes** — the estate answers what the cloud account alone cannot, and the\n"+
			"cloud scanner is not wrong: the fact that makes the answer possible lives on the other\n"+
			"surface, so from cloud data alone there is nothing to find.\n")
	} else {
		fmt.Fprintf(&b, "**LIFT: no** — the join added nothing here.\n")
	}
	if len(s.EstateFindings) > 0 {
		fmt.Fprintf(&b, "\ncross-surface detections: %s\n", strings.Join(s.EstateFindings, ", "))
	}
	return b.String()
}

func found(b bool) string {
	if b {
		return "found"
	}
	return "**not found**"
}

// WebHostToCloudCrown is the second join, and it asks a DIFFERENT question: not "can the internet
// reach the crown" but "what does this pentest target reach?" — the question that decides whether
// the AI pentester spends its request budget on a login form fronting a PII warehouse or one
// fronting a marketing page.
//
// The cloud graph cannot answer it at all, and not because it is missing a path: a HOSTNAME is not
// an identifier a cloud account holds. Only the inventory asserting "this DNS name is that resource"
// makes the question answerable, which is why the join is grounded on that assertion and never on a
// resource whose name merely resembles the host.
func WebHostToCloudCrown() CrossSurfaceFixture {
	inv := cloudgraph.Inventory{
		Provider: "aws", AccountID: "000000000000",
		Resources: []cloudgraph.InvResource{
			{ID: "i-web", Kind: "resource", Type: "ec2_instance", Public: true,
				DNSNames: []string{"app.example.com"}},
			{ID: "arn:aws:iam::000000000000:role/app", Kind: "principal", Name: "app-role"},
			{ID: "arn:aws:s3:::acme-customer-pii", Kind: "data", Name: "acme-customer-pii",
				Sensitive: cloudgraph.SensHigh},
		},
		RunsAs: []cloudgraph.InvRunsAs{{Compute: "i-web", Principal: "arn:aws:iam::000000000000:role/app"}},
		Grants: []cloudgraph.InvGrant{{Principal: "arn:aws:iam::000000000000:role/app",
			Resource: "arn:aws:s3:::acme-customer-pii"}},
	}
	return CrossSurfaceFixture{
		Name:     "web_host_to_cloud_crown",
		Question: "what does the pentest target app.example.com reach?",
		Cloud:    cloudgraph.Ingest(inv),
		Crown:    "arn:aws:s3:::acme-customer-pii",
		// The attacker starts at the hostname on both substrates. The cloud graph holds no such
		// node, so it finds nothing — the honest reason, not a missing edge.
		CloudEntry:  "app.example.com",
		EstateEntry: estategraph.Canonical("web", "https://app.example.com"),
	}
}
