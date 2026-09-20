package awsfetch

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// FunctionReader reads the account's Lambda functions: the identity each executes with (its
// execution role — the runs_as edge, and the step every "land on the function, inherit its role"
// path runs through) and whether a function URL exposes it to the internet without auth.
//
// Without this the live path carried no serverless compute at all, so a function reachable from
// the internet that runs as an admin role was invisible on a live account and visible only if a
// snapshot naming it was POSTed — the coverage line said so, and nobody reads a coverage line
// looking for the attack path it explains the absence of.
type FunctionReader interface {
	ListFunctions(ctx context.Context) ([]Function, error)
}

// Function is one Lambda function as the lister reports it.
type Function struct {
	ARN     string
	Name    string
	Region  string
	RoleARN string
	// PublicURL is true when a function URL exists with AuthType NONE — anyone on the internet may
	// invoke it. A URL with IAM auth is not public and is not reported as such.
	PublicURL bool
}

type lambdaAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListFunctionUrlConfigs(ctx context.Context, in *lambda.ListFunctionUrlConfigsInput, opts ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error)
}

// LambdaLister reads through the connected read-only role. lambda:ListFunctions and
// lambda:ListFunctionUrlConfigs are READ permissions (ViewOnlyAccess carries the first; the second
// is in ReadOnlyAccess) — a role lacking the URL read reports functions with PublicURL false and
// the fetcher notes the URL read was skipped, never asserting "not public" for a URL it could not see.
type LambdaLister struct {
	Region     string
	RoleARN    string
	ExternalID string

	api lambdaAPI // injected in tests
}

func NewLambdaLister(region, roleARN, externalID string) *LambdaLister {
	return &LambdaLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (l *LambdaLister) client(ctx context.Context) (lambdaAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return lambda.NewFromConfig(cfg), nil
}

func (l *LambdaLister) ListFunctions(ctx context.Context) ([]Function, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	var out []Function
	var marker *string
	for {
		res, err := api.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: list functions: %w", err)
		}
		for _, f := range res.Functions {
			fn := Function{ARN: aws.ToString(f.FunctionArn), Name: aws.ToString(f.FunctionName), Region: l.Region, RoleARN: aws.ToString(f.Role)}
			fn.PublicURL = l.publicURL(ctx, api, fn.Name)
			out = append(out, fn)
		}
		if res.NextMarker == nil || aws.ToString(res.NextMarker) == "" {
			break
		}
		marker = res.NextMarker
	}
	return out, nil
}

// publicURL reports whether any function URL has AuthType NONE. A read failure is FALSE: an unread
// URL config is not evidence the function is private, and the caller cannot tell the two apart
// from this bool alone — which is why the fetcher records the read separately.
func (l *LambdaLister) publicURL(ctx context.Context, api lambdaAPI, name string) bool {
	res, err := api.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{FunctionName: aws.String(name)})
	if err != nil {
		return false
	}
	for _, c := range res.FunctionUrlConfigs {
		if c.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
			return true
		}
	}
	return false
}
