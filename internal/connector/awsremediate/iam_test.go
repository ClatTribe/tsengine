package awsremediate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAM struct {
	owner   string
	lookErr error
	updErr  error
	updated *iam.UpdateAccessKeyInput
}

func (f *fakeIAM) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if f.lookErr != nil {
		return nil, f.lookErr
	}
	var name *string
	if f.owner != "" {
		name = aws.String(f.owner)
	}
	return &iam.GetAccessKeyLastUsedOutput{UserName: name}, nil
}

func (f *fakeIAM) UpdateAccessKey(_ context.Context, in *iam.UpdateAccessKeyInput, _ ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
	f.updated = in
	if f.updErr != nil {
		return nil, f.updErr
	}
	return &iam.UpdateAccessKeyOutput{}, nil
}

// The key is set INACTIVE (never deleted) for exactly the user IAM names as its owner.
func TestDeactivateAccessKey_SetsInactiveForTheOwnerIAMNames(t *testing.T) {
	fake := &fakeIAM{owner: "ci-deploy"}
	w := NewS3Writer("us-east-1", "", "")
	w.newIAM = func(context.Context) (iamAccessKeyAPI, error) { return fake, nil }
	if err := w.DeactivateAccessKey(context.Background(), "AKIAIOSFODNN7EXAMPLE"); err != nil {
		t.Fatal(err)
	}
	if fake.updated == nil || aws.ToString(fake.updated.UserName) != "ci-deploy" || fake.updated.Status != iamtypes.StatusTypeInactive ||
		aws.ToString(fake.updated.AccessKeyId) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("UpdateAccessKey: %+v", fake.updated)
	}
}

// Refusals: not a key id; an owner IAM will not name (a root key); a denied write surfaces as itself.
func TestDeactivateAccessKey_RefusesAndSurfacesErrors(t *testing.T) {
	w := NewS3Writer("us-east-1", "", "")
	w.newIAM = func(context.Context) (iamAccessKeyAPI, error) { return &fakeIAM{owner: "x"}, nil }
	if err := w.DeactivateAccessKey(context.Background(), "not-a-key"); err == nil || !strings.Contains(err.Error(), "not an AWS access key id") {
		t.Errorf("bad id: %v", err)
	}
	root := &fakeIAM{owner: ""}
	w.newIAM = func(context.Context) (iamAccessKeyAPI, error) { return root, nil }
	if err := w.DeactivateAccessKey(context.Background(), "AKIAIOSFODNN7EXAMPLE"); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("ownerless key: %v", err)
	}
	if root.updated != nil {
		t.Error("an ownerless key must not be touched")
	}
	denied := &fakeIAM{owner: "ci", updErr: errors.New("AccessDenied: iam:UpdateAccessKey")}
	w.newIAM = func(context.Context) (iamAccessKeyAPI, error) { return denied, nil }
	if err := w.DeactivateAccessKey(context.Background(), "ASIAIOSFODNN7EXAMPLE"); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("a denied write must surface, never read as revoked: %v", err)
	}
}
