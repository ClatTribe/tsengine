package awsfetch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// --- Lambda ---

type fakeLambdaAPI struct {
	urls   map[string]lambdatypes.FunctionUrlAuthType // function name → auth type of its URL
	urlErr error
}

func (f fakeLambdaAPI) ListFunctions(_ context.Context, in *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if in.Marker == nil {
		return &lambda.ListFunctionsOutput{Functions: []lambdatypes.FunctionConfiguration{
			{FunctionArn: aws.String("arn:aws:lambda:us-east-1:1:function:webhook"), FunctionName: aws.String("webhook"), Role: aws.String("arn:aws:iam::1:role/webhook-exec")},
		}, NextMarker: aws.String("p2")}, nil
	}
	return &lambda.ListFunctionsOutput{Functions: []lambdatypes.FunctionConfiguration{
		{FunctionArn: aws.String("arn:aws:lambda:us-east-1:1:function:nightly"), FunctionName: aws.String("nightly"), Role: aws.String("arn:aws:iam::1:role/nightly-exec")},
	}}, nil
}

func (f fakeLambdaAPI) ListFunctionUrlConfigs(_ context.Context, in *lambda.ListFunctionUrlConfigsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error) {
	if f.urlErr != nil {
		return nil, f.urlErr
	}
	if t, ok := f.urls[aws.ToString(in.FunctionName)]; ok {
		return &lambda.ListFunctionUrlConfigsOutput{FunctionUrlConfigs: []lambdatypes.FunctionUrlConfig{{AuthType: t}}}, nil
	}
	return &lambda.ListFunctionUrlConfigsOutput{}, nil
}

func TestLambdaLister_PagesAndReportsOnlyAnUnauthenticatedURLAsPublic(t *testing.T) {
	l := &LambdaLister{Region: "us-east-1", api: fakeLambdaAPI{urls: map[string]lambdatypes.FunctionUrlAuthType{
		"webhook": lambdatypes.FunctionUrlAuthTypeNone, "nightly": lambdatypes.FunctionUrlAuthTypeAwsIam,
	}}}
	fns, err := l.ListFunctions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 2 {
		t.Fatalf("both pages must be read: %+v", fns)
	}
	byName := map[string]Function{}
	for _, f := range fns {
		byName[f.Name] = f
	}
	if !byName["webhook"].PublicURL || byName["webhook"].RoleARN != "arn:aws:iam::1:role/webhook-exec" {
		t.Errorf("a NONE-auth URL is public and the execution role must ride along: %+v", byName["webhook"])
	}
	if byName["nightly"].PublicURL {
		t.Error("an IAM-auth URL is not public")
	}
	// A URL read failure is not evidence of privacy — the bool stays false and says nothing.
	l2 := &LambdaLister{Region: "us-east-1", api: fakeLambdaAPI{urlErr: errors.New("AccessDenied: lambda:ListFunctionUrlConfigs")}}
	fns2, _ := l2.ListFunctions(context.Background())
	for _, f := range fns2 {
		if f.PublicURL {
			t.Error("an unread URL config must not be asserted public")
		}
	}
}

// --- RDS ---

type fakeRDSAPI struct{}

func (fakeRDSAPI) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{
		{DBInstanceArn: aws.String("arn:aws:rds:us-east-1:1:db:customers"), DBInstanceIdentifier: aws.String("customers"), Engine: aws.String("postgres"),
			PubliclyAccessible: aws.Bool(true), StorageEncrypted: aws.Bool(false), Endpoint: &rdstypes.Endpoint{Port: aws.Int32(5432)},
			VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: aws.String("sg-db")}},
			TagList:           []rdstypes.Tag{{Key: aws.String("data-classification"), Value: aws.String("PII")}}},
		{DBInstanceArn: aws.String("arn:aws:rds:us-east-1:1:db:metrics"), DBInstanceIdentifier: aws.String("metrics"), Engine: aws.String("mysql"),
			PubliclyAccessible: aws.Bool(false), StorageEncrypted: aws.Bool(true), Endpoint: &rdstypes.Endpoint{Port: aws.Int32(3306)},
			TagList: []rdstypes.Tag{{Key: aws.String("team"), Value: aws.String("data")}}},
	}}, nil
}

func TestRDSLister_ReadsPublicPortSGsEncryptionAndDeclaredSensitivity(t *testing.T) {
	l := &RDSLister{Region: "us-east-1", api: fakeRDSAPI{}}
	dbs, err := l.ListDatabases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 2 {
		t.Fatalf("%+v", dbs)
	}
	c := dbs[0]
	if !c.Public || c.Encrypted || c.Port != 5432 || len(c.SGIDs) != 1 || !c.Sensitive || c.Engine != "postgres" {
		t.Errorf("customers db: %+v", c)
	}
	if m := dbs[1]; m.Public || !m.Encrypted || m.Sensitive {
		t.Errorf("metrics db: sensitivity must come only from a declared tag, never the engine or name: %+v", m)
	}
}

// --- the fetch integration: new surfaces are named, and instance profiles resolve to roles ---

type fakeFunctions struct {
	out []Function
	err error
}

func (f fakeFunctions) ListFunctions(context.Context) ([]Function, error) { return f.out, f.err }

type fakeDatabases struct{ out []Database }

func (f fakeDatabases) ListDatabases(context.Context) ([]Database, error) { return f.out, nil }

type stubCompute struct{ ins []Instance }

func (f stubCompute) ListCompute(context.Context) ([]Instance, []SecurityGroup, error) {
	return f.ins, nil, nil
}

// fakeIAMProfiles is the existing principal fake plus an (empty) instance-profile resolution, for
// tests that claim a COMPLETE identity read.
type fakeIAMProfiles struct{ fakeIAM }

func (fakeIAMProfiles) ListInstanceProfiles(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

// fakeIAMWithProfiles is an IAMReader that can also resolve instance profiles.
type fakeIAMWithProfiles struct {
	profiles map[string]string
	err      error
}

func (f fakeIAMWithProfiles) ListPrincipals(context.Context) ([]Principal, error) { return nil, nil }
func (f fakeIAMWithProfiles) ListInstanceProfiles(context.Context) (map[string]string, error) {
	return f.profiles, f.err
}

func TestFetch_ReadsFunctionsAndDatabasesAndResolvesInstanceProfiles(t *testing.T) {
	f := Fetcher{
		AccountID:  "1",
		Buckets:    fakeLister{},
		Principals: fakeIAMWithProfiles{profiles: map[string]string{"arn:aws:iam::1:instance-profile/web": "arn:aws:iam::1:role/web-role"}},
		Compute:    stubCompute{ins: []Instance{{ID: "i-1", ProfileARN: "arn:aws:iam::1:instance-profile/web"}, {ID: "i-2"}}},
		Functions:  fakeFunctions{out: []Function{{ARN: "arn:aws:lambda:us-east-1:1:function:hook", Name: "hook", RoleARN: "arn:aws:iam::1:role/hook", PublicURL: true}}},
		Databases:  fakeDatabases{out: []Database{{ARN: "arn:aws:rds:us-east-1:1:db:c", ID: "c", Public: true, Port: 5432}}},
	}
	res, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Sources, ",")
	for _, want := range []string{"lambda", "rds", "ec2", "iam"} {
		if !strings.Contains(joined, want) {
			t.Errorf("source %s not recorded: %v", want, res.Sources)
		}
	}
	if len(res.Raw.Functions) != 1 || res.Raw.Functions[0].RoleARN != "arn:aws:iam::1:role/hook" || !res.Raw.Functions[0].PublicURL {
		t.Errorf("functions: %+v", res.Raw.Functions)
	}
	if len(res.Raw.Databases) != 1 || !res.Raw.Databases[0].Public || res.Raw.Databases[0].Port != 5432 {
		t.Errorf("databases: %+v", res.Raw.Databases)
	}
	if res.Raw.Instances[0].RoleARN != "arn:aws:iam::1:role/web-role" {
		t.Errorf("the instance profile must resolve to its role through IAM: %+v", res.Raw.Instances[0])
	}
	if res.Raw.Instances[1].RoleARN != "" {
		t.Errorf("an instance with no profile carries no role: %+v", res.Raw.Instances[1])
	}
	if _, skipped := res.Skipped["instance-profiles"]; skipped {
		t.Errorf("profiles resolved, nothing to skip: %v", res.Skipped)
	}

	// Readers absent or failing are NAMED as skipped surfaces, never an account with none.
	f2 := Fetcher{AccountID: "1", Buckets: fakeLister{}, Functions: fakeFunctions{err: errors.New("AccessDenied: lambda:ListFunctions")}}
	res2, err := f2.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res2.Skipped["lambda"], "AccessDenied") || !strings.Contains(res2.Skipped["rds"], "no database reader") {
		t.Errorf("skipped surfaces must be named with their reason: %v", res2.Skipped)
	}
	cov := res2.Coverage()
	if !strings.Contains(cov, "lambda") || !strings.Contains(cov, "rds") {
		t.Errorf("the coverage line must name the unread surfaces: %s", cov)
	}
}

// The IAM lister resolves profiles through the SDK listing, first role only, paged.
type fakeIAMProfilesAPI struct{ *fakeIAMAPI }

func (fakeIAMProfilesAPI) ListInstanceProfiles(_ context.Context, in *iam.ListInstanceProfilesInput, _ ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error) {
	if in.Marker == nil {
		return &iam.ListInstanceProfilesOutput{InstanceProfiles: []iamtypes.InstanceProfile{
			{Arn: aws.String("arn:aws:iam::1:instance-profile/web"), Roles: []iamtypes.Role{{Arn: aws.String("arn:aws:iam::1:role/web-role")}}},
		}, IsTruncated: true, Marker: aws.String("m2")}, nil
	}
	return &iam.ListInstanceProfilesOutput{InstanceProfiles: []iamtypes.InstanceProfile{
		{Arn: aws.String("arn:aws:iam::1:instance-profile/empty")},
	}}, nil
}

func TestIAMLister_ListInstanceProfilesMapsProfileToRole(t *testing.T) {
	l := &IAMLister{api: fakeIAMProfilesAPI{fakeIAMAPI: &fakeIAMAPI{}}}
	m, err := l.ListInstanceProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m["arn:aws:iam::1:instance-profile/web"] != "arn:aws:iam::1:role/web-role" || len(m) != 1 {
		t.Errorf("profile map: %v (a profile with no role maps to nothing)", m)
	}
}
