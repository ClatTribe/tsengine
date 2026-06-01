package cloudquery

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// Large procedural dataset generator — a "sufficiently real, large" emulated
// CloudQuery account to test the engine against at scale. It produces hundreds of
// resources with realistic policy variety + lots of config-bad NOISE, then plants
// a controlled set of genuinely-exploitable paths and config-bad-but-inert decoys
// across every archetype the engine reasons over. The answer key (real targets +
// the planted inert findings) is established INDEPENDENTLY by cloudiam, and every
// planted scenario is validated — a mis-built one is rejected, never scored.
//
// The benchmark this enables: many prowler findings (noise), a handful of genuine
// attack paths, and the engineer must find the genuine ones, downgrade the inert
// ones, and report ZERO false paths across the whole account.

// LargeOpts parameterizes the generated account.
type LargeOpts struct {
	Seed       int64
	Principals int // benign IAM roles
	Buckets    int // benign S3 buckets
	Instances  int // benign EC2 instances
	RealPaths  int // planted genuinely-exploitable paths
	Decoys     int // planted config-bad-but-inert postures
}

// SizedLargeOpts derives a balanced LargeOpts from a single size knob.
func SizedLargeOpts(seed int64, size int) LargeOpts {
	if size <= 0 {
		size = 300
	}
	return LargeOpts{
		Seed: seed, Principals: size, Buckets: size * 4 / 5, Instances: size * 4 / 5,
		RealPaths: max(6, size/20), Decoys: max(10, size/8),
	}
}

type builder struct {
	rng   *rand.Rand
	t     *Tables
	real  map[string]bool
	inert map[string]bool
	scps  []json.RawMessage
	n     int
}

func newBuilder(seed int64) *builder {
	b := &builder{
		rng: rand.New(rand.NewSource(seed)), //nolint:gosec // benchmark fixture, not crypto
		t:   &Tables{}, real: map[string]bool{}, inert: map[string]bool{},
	}
	b.scps = raws(json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)) // org FullAWSAccess
	b.addSG("sg-open", true)
	for i := 0; i < 6; i++ {
		b.addSG(fmt.Sprintf("sg-closed-%d", i), false)
	}
	return b
}

func (b *builder) uid(p string) string { b.n++; return fmt.Sprintf("%s-%d", p, b.n) }

func bucketARN(name string) string { return "arn:aws:s3:::" + name }
func roleARN(name string) string   { return "arn:aws:iam::123456789012:role/" + name }
func ec2ARN(name string) string    { return "arn:aws:ec2:us-east-1:123456789012:instance/" + name }

var ec2Trust = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"ec2.amazonaws.com"}]}`)

func (b *builder) addSG(id string, open bool) {
	b.t.SecurityGroups = append(b.t.SecurityGroups, SecurityGroup{ID: id, Name: id, OpenIngressFromInternet: open})
}

func (b *builder) addBucket(name string, sensitive, public, mfaDelete bool, policy json.RawMessage) string {
	arn := bucketARN(name)
	bk := S3Bucket{ARN: arn, Name: name, Region: "us-east-1", MFADelete: mfaDelete, Policy: policy}
	if sensitive {
		bk.Tags = map[string]string{"classification": "pii"}
	}
	if public {
		bk.PolicyAllowsPublic = true
	} else {
		bk.BlockPublicACLs, bk.BlockPublicPolicy = true, true
	}
	b.t.S3Buckets = append(b.t.S3Buckets, bk)
	return arn
}

func (b *builder) addRole(name string, identity []json.RawMessage, boundary json.RawMessage) string {
	arn := roleARN(name)
	b.t.IAMRoles = append(b.t.IAMRoles, IAMRole{ARN: arn, Name: name, AssumeRolePolicyDocument: ec2Trust, InlinePolicies: identity, PermissionsBoundary: boundary})
	return arn
}

// addPublicCompute attaches a public EC2 (open SG) running the given role.
func (b *builder) addPublicCompute(role string) {
	b.t.EC2Instances = append(b.t.EC2Instances, EC2Instance{
		ARN: ec2ARN(b.uid("pub")), Name: b.uid("i"), PublicIPAddress: fmt.Sprintf("203.0.113.%d", b.rng.Intn(254)+1),
		IAMInstanceProfileRoleARN: role, SecurityGroupIDs: []string{"sg-open"},
	})
}

// addBenign fills the account with realistic noise: private compute, scoped roles,
// and config-bad-but-harmless buckets (the findings the engineer must wade
// through). None of it forms a path from the internet to a crown jewel.
func (b *builder) addBenign(o LargeOpts) {
	var benign []string
	for i := 0; i < o.Buckets; i++ {
		public := b.rng.Intn(10) == 0 // ~10% public (non-sensitive)
		mfa := b.rng.Intn(3) != 0     // ~33% missing MFA delete (a finding)
		benign = append(benign, b.addBucket(b.uid("logs"), false, public, mfa, nil))
	}
	for i := 0; i < o.Principals; i++ {
		tgt := benign[b.rng.Intn(len(benign))]
		role := b.addRole(b.uid("app"), raws(allowDoc("s3:GetObject", tgt)), nil)
		if i < o.Instances { // most benign compute is PRIVATE → not an entry point
			b.t.EC2Instances = append(b.t.EC2Instances, EC2Instance{
				ARN: ec2ARN(b.uid("priv")), Name: b.uid("i"), IAMInstanceProfileRoleARN: role,
				SecurityGroupIDs: []string{fmt.Sprintf("sg-closed-%d", b.rng.Intn(6))},
			})
		}
	}
}

// --- real paths (must-find) ---

func (b *builder) plantNetworkData(i int) error {
	bkt := b.addBucket(b.uid("crownjewel-data"), true, false, false, nil)
	id := raws(allowDoc("s3:GetObject", bkt))
	role := b.addRole(b.uid("data-svc"), id, nil)
	b.addPublicCompute(role)
	if ok, cond := canReadBucket(role, bkt, parseDocs(id), nil, parseDocs(b.scps), nil); !ok || cond {
		return fmt.Errorf("networkData %d: role must unconditionally read %s", i, bkt)
	}
	b.real[bkt] = true
	return nil
}

func (b *builder) plantResourcePolicy(i int) error {
	name := b.uid("crownjewel-respol")
	bkt := bucketARN(name)
	role := b.addRole(b.uid("reader"), nil, nil) // NO identity grant
	pol := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + role + `"},"Action":"s3:GetObject","Resource":"` + bkt + `/*"}]}`)
	b.addBucket(name, true, false, false, pol)
	b.addPublicCompute(role)
	if ok, _ := canReadBucket(role, bkt, nil, nil, parseDocs(b.scps), parseDoc(pol)); !ok {
		return fmt.Errorf("resourcePolicy %d: role must read %s via the bucket policy", i, bkt)
	}
	b.real[bkt] = true
	return nil
}

func (b *builder) plantPrivesc(i int) error {
	esc := raws(allowDoc("iam:CreatePolicyVersion", "*"))
	role := b.addRole(b.uid("ci-escalator"), esc, nil)
	b.addPublicCompute(role)
	if _, ok := detectPrivesc(role, parseDocs(esc), nil, parseDocs(b.scps)); !ok {
		return fmt.Errorf("privesc %d: role must escalate to admin", i)
	}
	b.real[cloudgraph.AdminID] = true
	return nil
}

// --- decoys (must-downgrade) ---

func (b *builder) plantBoundaryPrivesc(i int) error {
	esc := raws(allowDoc("iam:CreatePolicyVersion", "*"))
	boundary := allowDoc("s3:Get*", "*")
	role := b.addRole(b.uid("bnd-escalator"), esc, boundary)
	b.addPublicCompute(role)
	if _, ok := detectPrivesc(role, parseDocs(esc), nil, nil); !ok {
		return fmt.Errorf("boundaryPrivesc %d: must escalate without the boundary", i)
	}
	if _, ok := detectPrivesc(role, parseDocs(esc), parseDoc(boundary), nil); ok {
		return fmt.Errorf("boundaryPrivesc %d: boundary must block the escalation", i)
	}
	b.inert[FindingID("iam_policy_allows_privilege_escalation", role)] = true
	return nil
}

func (b *builder) plantTrustDenied(i int) error {
	bkt := b.addBucket(b.uid("decoy-trust-data"), true, false, false, nil)
	trust := allowDoc("sts:AssumeRole", roleARN("trusted-pipeline-only")) // does NOT name the source
	targetName := b.uid("priv-target")
	target := roleARN(targetName)
	b.t.IAMRoles = append(b.t.IAMRoles, IAMRole{ARN: target, Name: targetName, AssumeRolePolicyDocument: trust, InlinePolicies: raws(allowDoc("s3:GetObject", bkt))})
	src := b.addRole(b.uid("would-assume"), raws(allowDoc("sts:AssumeRole", target)), nil)
	b.addPublicCompute(src)
	if ok, _ := cloudiam.Allows("sts:AssumeRole", src, parseDoc(trust)); ok {
		return fmt.Errorf("trustDenied %d: target must NOT trust the source", i)
	}
	b.inert[FindingID("s3_bucket_no_mfa_delete", bkt)] = true
	return nil
}

func (b *builder) plantScpDenied(i int) error {
	bkt := b.addBucket(b.uid("decoy-scp-data"), true, false, false, nil)
	id := raws(allowDoc("s3:GetObject", bkt))
	role := b.addRole(b.uid("scp-blocked"), id, nil)
	b.addPublicCompute(role)
	b.scps = append(b.scps, json.RawMessage(`{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":["`+bkt+`","`+bkt+`/*"]}]}`))
	if ok, _ := canReadBucket(role, bkt, parseDocs(id), nil, nil, nil); !ok {
		return fmt.Errorf("scpDenied %d: role must read %s without the SCP", i, bkt)
	}
	if ok, _ := canReadBucket(role, bkt, parseDocs(id), nil, parseDocs(b.scps), nil); ok {
		return fmt.Errorf("scpDenied %d: the SCP must block reading %s", i, bkt)
	}
	b.inert[FindingID("s3_bucket_no_mfa_delete", bkt)] = true
	return nil
}

func (b *builder) plantConditionGated(i int) error {
	name := b.uid("decoy-mfa-data")
	bkt := bucketARN(name)
	id := raws(json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["` + bkt + `","` + bkt + `/*"],"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`))
	b.addBucket(name, true, false, false, nil)
	role := b.addRole(b.uid("mfa-gated"), id, nil)
	b.addPublicCompute(role)
	if ok, cond := canReadBucket(role, bkt, parseDocs(id), nil, parseDocs(b.scps), nil); !ok || !cond {
		return fmt.Errorf("conditionGated %d: read of %s must be allowed-but-conditional", i, bkt)
	}
	b.inert[FindingID("s3_bucket_no_mfa_delete", bkt)] = true
	return nil
}

func (b *builder) plantNonSensitivePublic(i int) error {
	bkt := b.addBucket(b.uid("decoy-public"), false, true, true, nil)
	b.inert[FindingID("s3_bucket_public_access", bkt)] = true
	return nil
}

func (b *builder) plantIsolatedSensitive(i int) error {
	bkt := b.addBucket(b.uid("decoy-isolated"), true, false, false, nil) // sensitive, no grant, not public
	b.inert[FindingID("s3_bucket_no_mfa_delete", bkt)] = true
	return nil
}

// GenerateLarge builds the large account with its cloudiam-validated answer key.
func GenerateLarge(o LargeOpts) (*Dataset, error) {
	if o.Buckets <= 0 {
		o = SizedLargeOpts(o.Seed, 0)
	}
	b := newBuilder(o.Seed)
	b.addBenign(o)

	reals := []func(int) error{b.plantNetworkData, b.plantResourcePolicy, b.plantPrivesc}
	for i := 0; i < o.RealPaths; i++ {
		if err := reals[i%len(reals)](i); err != nil {
			return nil, err
		}
	}
	decoys := []func(int) error{
		b.plantBoundaryPrivesc, b.plantTrustDenied, b.plantScpDenied,
		b.plantConditionGated, b.plantNonSensitivePublic, b.plantIsolatedSensitive,
	}
	for i := 0; i < o.Decoys; i++ {
		if err := decoys[i%len(decoys)](i); err != nil {
			return nil, err
		}
	}
	b.t.SCPs = b.scps

	return &Dataset{Tables: b.t, AnswerKey: AnswerKey{
		RealTargets:   sortedKeys(b.real),
		InertFindings: sortedKeys(b.inert),
	}}, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Stats returns a human summary of the dataset shape.
func (ds *Dataset) Stats() string {
	t := ds.Tables
	return fmt.Sprintf("%d S3, %d IAM roles, %d EC2, %d SG, %d SCP — %d real target(s), %d planted inert finding(s)",
		len(t.S3Buckets), len(t.IAMRoles), len(t.EC2Instances), len(t.SecurityGroups), len(t.SCPs),
		len(ds.AnswerKey.RealTargets), len(ds.AnswerKey.InertFindings))
}
