package ciproof

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

// fakeProber records whether it was asked at all — the point of several tests below.
type fakeProber struct {
	verdict cloudagent.Verdict
	why     string
	calls   int
}

func (f *fakeProber) CanPerform(context.Context, string, string, string) (cloudagent.ProbeResult, error) {
	f.calls++
	return cloudagent.ProbeResult{Verdict: f.verdict, Why: f.why, Detail: "matched AllowProdRead"}, nil
}
func (f *fakeProber) Coverage() string { return "fake" }

// trustPolicy admitting exactly one repository's main branch.
func policyFor(sub string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
	  "Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"` + sub + `"}}}]}`
}

// policyLike is policyFor's wildcarding twin — StringLike, the operator under which an asterisk
// actually means something.
func policyLike(sub string) string {
	return strings.Replace(policyFor(sub), `"StringEquals"`, `"StringLike"`, 1)
}

func role(policy string) ghoidc.Role {
	return ghoidc.Role{ARN: "arn:aws:iam::111122223333:role/deploy", Name: "deploy",
		Account: "111122223333", TrustPolicy: policy}
}

func wf(repo, ref string) ghoidc.WorkflowContext {
	owner, name, _ := strings.Cut(repo, "/")
	return ghoidc.WorkflowContext{Owner: owner, Repo: name, Ref: ref}
}

var target = Target{Action: "s3:GetObject", Resource: "arn:aws:s3:::customer-exports/*"}

// THE CLAIM THIS PACKAGE EXISTS FOR. Each half is unremarkable alone; together they are the finding.
func TestProve_BothHalvesEstablished(t *testing.T) {
	p := &fakeProber{verdict: cloudagent.VerdictAllow}
	c := Prove(context.Background(), role(policyFor("repo:acme/web:ref:refs/heads/main")),
		wf("acme/web", "refs/heads/main"), target, p)

	if c.Status != StatusAuthorized {
		t.Fatalf("status = %q, want %q (trust: %+v, perm: %+v)", c.Status, StatusAuthorized, c.Trust, c.Permission)
	}
	if c.Trust.Repository != "acme/web" {
		t.Errorf("the actor is not named: %+v", c.Trust)
	}
	// C1: authorization end to end is not an exploit, and the summary is the sentence a human reads.
	if !strings.Contains(c.Summary, "not a demonstrated exploit") {
		t.Errorf("the summary claims more than authorization:\n%s", c.Summary)
	}
}

// A trust refusal CLOSES the chain, and must not spend a live provider call. Read-only is not free:
// every simulate writes to the customer's audit trail and consumes their quota (ADR 0024 C10).
func TestProve_ATrustRefusalDoesNotSpendAProviderCall(t *testing.T) {
	p := &fakeProber{verdict: cloudagent.VerdictAllow}
	c := Prove(context.Background(), role(policyFor("repo:acme/web:ref:refs/heads/main")),
		wf("attacker/evil", "refs/heads/main"), target, p)

	if c.Status != StatusRefusedAtTrust {
		t.Fatalf("status = %q, want %q", c.Status, StatusRefusedAtTrust)
	}
	if p.calls != 0 {
		t.Errorf("asked the provider %d times after the chain was already closed", p.calls)
	}
	// C3: authoritative for the subject tested, and no further.
	if !strings.Contains(c.Summary, "no other workflow") {
		t.Errorf("the refusal overclaims — it must not imply nobody can assume the role:\n%s", c.Summary)
	}
}

// Trust established, permission refused: the federation is REAL even though this reach is not.
// Reporting it as "no chain" would hide a live federation that another target might reach.
func TestProve_PermissionRefusedStillReportsTheFederation(t *testing.T) {
	p := &fakeProber{verdict: cloudagent.VerdictDeny}
	c := Prove(context.Background(), role(policyFor("repo:acme/web:ref:refs/heads/main")),
		wf("acme/web", "refs/heads/main"), target, p)

	if c.Status != StatusRefusedAtPermission {
		t.Fatalf("status = %q, want %q", c.Status, StatusRefusedAtPermission)
	}
	if !strings.Contains(c.Summary, "federation is real") {
		t.Errorf("a refused reach hid the live federation behind it:\n%s", c.Summary)
	}
}

// Half a chain is not a chain, and the two ways of being half must not read alike.
func TestProve_AnUnaskedOrUnansweredPermissionIsUndetermined(t *testing.T) {
	r, w := role(policyFor("repo:acme/web:ref:refs/heads/main")), wf("acme/web", "refs/heads/main")

	// No prober wired at all.
	c := Prove(context.Background(), r, w, target, nil)
	if c.Status != StatusUndetermined {
		t.Fatalf("no prober: status = %q, want undetermined", c.Status)
	}
	if c.Permission == nil || c.Permission.Asked {
		t.Error("a question never put must not be recorded as asked")
	}

	// Asked, and the provider could not answer.
	p := &fakeProber{verdict: cloudagent.VerdictUnknown, why: "throttled"}
	c2 := Prove(context.Background(), r, w, target, p)
	if c2.Status != StatusUndetermined {
		t.Fatalf("unknown verdict: status = %q, want undetermined", c2.Status)
	}
	if c2.Permission == nil || !c2.Permission.Asked {
		t.Error("a question we DID put must be recorded as asked — otherwise coverage cannot be reported")
	}
	if !strings.Contains(c2.Summary, "throttled") {
		t.Errorf("the reason the provider could not answer is not carried: %s", c2.Summary)
	}
}

// THE WILDCARD LIVES IN THE POLICY, NOT IN THE SUBJECT WE TESTED WITH, and getting that backwards is
// easy: the tested subject is always concrete, so checking IT for an asterisk finds nothing and
// silently reports "only acme/anything can assume this role" about a policy admitting the whole org.
//
// The property that matters is not whether a repository is named — it is that a reader must not
// conclude only that ONE repository can assume the role. Understating the blast radius is the
// dangerous direction here, because the reader's next move is deciding how urgently to re-scope.
func TestProve_APolicyWildcardIsDisclosedNotHiddenBehindTheTestedRepo(t *testing.T) {
	c := Prove(context.Background(), role(policyLike("repo:acme/*:*")), wf("acme/anything", "refs/heads/main"),
		target, &fakeProber{verdict: cloudagent.VerdictAllow})

	if c.Trust.AdmitsPattern != "repo:acme/*:*" {
		t.Fatalf("the policy admits a whole class and the chain does not say so: %+v", c.Trust)
	}
	if !strings.Contains(c.Summary, "any other matching repo:acme/*:*") {
		t.Errorf("the summary lets a reader think one repository can reach this role:\n%s", c.Summary)
	}
}

// The mirror, and the reason the check must be on the operator rather than the asterisk: `*` under
// StringEquals is a LITERAL, so this policy matches a repository named "*" — nothing. Reporting it as
// a wildcard would raise a breadth alarm on a policy that is merely broken. ghoidc.Condition.Wildcard
// already encodes this, which is why it is reused rather than re-implemented.
func TestProve_AnAsteriskUnderStringEqualsIsNotAWildcard(t *testing.T) {
	c := Prove(context.Background(), role(policyFor("repo:acme/*:*")), wf("acme/anything", "refs/heads/main"),
		target, &fakeProber{verdict: cloudagent.VerdictAllow})
	if c.Trust.AdmitsPattern != "" {
		t.Fatalf("a literal asterisk under StringEquals was reported as a wildcard: %q", c.Trust.AdmitsPattern)
	}
}

// An UNDECIDED trust verdict is not a denial — ghoidc is explicit that reading it as one is how a
// real path gets dismissed — and nothing downstream of it is established either.
func TestProve_AnUndecidedTrustHalfIsNotADenial(t *testing.T) {
	p := &fakeProber{verdict: cloudagent.VerdictAllow}
	// An unparseable trust document: not assessed, and certainly not safe.
	c := Prove(context.Background(), role("{not json"), wf("acme/web", "refs/heads/main"), target, p)

	if c.Status == StatusRefusedAtTrust {
		t.Fatal("an undecided trust verdict was reported as a refusal — that dismisses a path we never evaluated")
	}
	if c.Status != StatusUndetermined {
		t.Fatalf("status = %q, want undetermined", c.Status)
	}
	if p.calls != 0 {
		t.Error("asked the provider a question with nothing to attach the answer to")
	}
}
