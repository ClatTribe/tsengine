package cloudiam

import "testing"

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*", "anything", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"s3:GetObject", "s3:GetObject", true},
		{"iam:?reateUser", "iam:CreateUser", true},
		{"ec2:Describe*", "ec2:DescribeInstances", true},
		{"s3:*Object", "s3:GetObject", true},
		{"s3:*Object", "s3:GetBucket", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func mustParse(t *testing.T, s string) *Document {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func TestEval_AllowWildcardAndDenyOverride(t *testing.T) {
	allowAll := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	if ok, _ := Allows("s3:GetObject", "arn:aws:s3:::b/x", allowAll); !ok {
		t.Error("s3:* should allow s3:GetObject")
	}
	if ok, _ := Allows("ec2:RunInstances", "*", allowAll); ok {
		t.Error("s3:* must not allow ec2:RunInstances")
	}
	// explicit deny wins over a broad allow
	deny := mustParse(t, `{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)
	if ok, _ := Allows("s3:GetObject", "arn:aws:s3:::b/x", allowAll, deny); ok {
		t.Error("explicit Deny must override Allow")
	}
}

func TestEval_ResourceScopingAndConditions(t *testing.T) {
	scoped := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}]}`)
	if ok, _ := Allows("s3:GetObject", "arn:aws:s3:::secret/k", scoped); !ok {
		t.Error("scoped allow should match the in-scope resource")
	}
	if ok, _ := Allows("s3:GetObject", "arn:aws:s3:::other/k", scoped); ok {
		t.Error("scoped allow must not match an out-of-scope resource")
	}
	cond := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	ok, conditional := Allows("sts:AssumeRole", "arn:aws:iam::1:role/r", cond)
	if !ok || !conditional {
		t.Errorf("conditioned allow should be allowed=%v conditional=%v (want true,true)", ok, conditional)
	}
}

func TestEval_NotAction(t *testing.T) {
	// Allow everything except iam:* — so s3:GetObject allowed, iam:CreateUser not.
	d := mustParse(t, `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`)
	if ok, _ := Allows("s3:GetObject", "*", d); !ok {
		t.Error("NotAction iam:* should still allow s3:GetObject")
	}
	if ok, _ := Allows("iam:CreateUser", "*", d); ok {
		t.Error("NotAction iam:* must exclude iam:CreateUser")
	}
}

func TestDetectPrivesc(t *testing.T) {
	// A principal that can iam:PassRole + lambda:CreateFunction + InvokeFunction
	// can escalate via PassRoleToNewLambda; also CreatePolicyVersion.
	doc := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":[
		"iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction","iam:CreatePolicyVersion"
	],"Resource":"*"}]}`)
	can := func(a string) bool { return CanDo(a, doc) }
	got := map[string]bool{}
	for _, tq := range DetectPrivesc(can) {
		got[tq.Name] = true
	}
	if !got["PassRoleToNewLambda"] {
		t.Error("should detect PassRoleToNewLambda")
	}
	if !got["CreateNewPolicyVersion"] {
		t.Error("should detect CreateNewPolicyVersion")
	}
	if got["PassRoleToNewEC2"] {
		t.Error("should NOT detect PassRoleToNewEC2 (no ec2:RunInstances)")
	}

	// A read-only principal escalates via nothing.
	ro := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","ec2:Describe*"],"Resource":"*"}]}`)
	if n := len(DetectPrivesc(func(a string) bool { return CanDo(a, ro) })); n != 0 {
		t.Errorf("read-only principal should enable 0 privesc techniques, got %d", n)
	}
}
