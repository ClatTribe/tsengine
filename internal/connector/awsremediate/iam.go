package awsremediate

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DeactivateAccessKey is the LIVE write behind the wedge's code → cloud "fixes it": a leaked
// access key found in a repository is already compromised, and scrubbing the file does nothing for
// the copies an attacker has. Until now the leaked-key action carried `aws_key_revoke` as a
// DIRECTIVE — a PR body telling the customer to revoke it — with no connector write path.
//
// DEACTIVATE, not delete. Setting the key Inactive is reversible (a human can re-activate a key
// that turned out to be in use by something nobody documented) and it stops the credential the
// same instant. Deletion is the customer's call once the blast radius is understood.
//
// The key's owner is resolved through IAM's own GetAccessKeyLastUsed (which returns the UserName
// the key belongs to), never by scanning users, so the write names exactly one principal. Needs
// iam:GetAccessKeyLastUsed + iam:UpdateAccessKey on the WRITE role — read-only onboarding roles do
// not carry them, and the resulting AccessDenied surfaces as itself, never as "revoked".
type iamAccessKeyAPI interface {
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
}

var accessKeyIDRe = regexp.MustCompile(`^(?:AKIA|ASIA)[A-Z0-9]{16}$`)

func (w *S3Writer) DeactivateAccessKey(ctx context.Context, keyID string) error {
	if !accessKeyIDRe.MatchString(keyID) {
		return fmt.Errorf("awsremediate: %q is not an AWS access key id", keyID)
	}
	client, err := w.iamClient(ctx)
	if err != nil {
		return fmt.Errorf("awsremediate: build iam client: %w", err)
	}
	owner, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(keyID)})
	if err != nil {
		return fmt.Errorf("awsremediate: GetAccessKeyLastUsed(%s): %w", keyID, err)
	}
	user := aws.ToString(owner.UserName)
	if user == "" {
		return fmt.Errorf("awsremediate: IAM names no owner for %s — it may be a root key, which this path will not touch", keyID)
	}
	if _, err := client.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: aws.String(keyID), UserName: aws.String(user), Status: iamtypes.StatusTypeInactive,
	}); err != nil {
		return fmt.Errorf("awsremediate: UpdateAccessKey(%s → Inactive) for %s: %w", keyID, user, err)
	}
	return nil
}

func (w *S3Writer) iamClient(ctx context.Context) (iamAccessKeyAPI, error) {
	if w.newIAM != nil {
		return w.newIAM(ctx)
	}
	region := w.Region
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	if w.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), w.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if w.ExternalID != "" {
				o.ExternalID = aws.String(w.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return iam.NewFromConfig(cfg), nil
}
