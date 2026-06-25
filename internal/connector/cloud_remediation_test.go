package connector

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

type recordingAWSWriter struct{ blocked string }

func (r *recordingAWSWriter) BlockS3PublicAccess(_ context.Context, bucket string) error {
	r.blocked = bucket
	return nil
}

// A connection that carries an enabled remediation config routes through the PER-TENANT writer
// built from the customer's own role — not the operator default.
func TestAWS_Apply_UsesPerTenantWriterFromConfig(t *testing.T) {
	perTenant := &recordingAWSWriter{}
	operatorDefault := &recordingAWSWriter{}
	var gotRegion, gotRole string
	a := &AWS{
		Region: "op-region",
		Writer: operatorDefault,
		WriterForConfig: func(region, roleARN string) AWSWriter {
			gotRegion, gotRole = region, roleARN
			return perTenant
		},
	}
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnAWS, Config: map[string]string{
		platform.CfgRemediationEnabled: "true",
		platform.CfgRemediationRole:    "arn:aws:iam::123:role/tsengine-remediate",
		platform.CfgRemediationRegion:  "us-east-1",
	}}
	act := platform.Action{ID: "act", Payload: map[string]any{"remediation_type": "s3_block_public_access", "target": "arn:aws:s3:::my-bucket"}}
	if err := a.Apply(context.Background(), conn, "", act); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if perTenant.blocked != "my-bucket" {
		t.Errorf("per-tenant writer should have blocked my-bucket, got %q", perTenant.blocked)
	}
	if operatorDefault.blocked != "" {
		t.Error("operator default must NOT be used when the connection has its own role")
	}
	if gotRole != "arn:aws:iam::123:role/tsengine-remediate" || gotRegion != "us-east-1" {
		t.Errorf("factory got wrong role/region: %q / %q", gotRole, gotRegion)
	}
}

// Without a remediation config the connection falls back to the operator-default writer.
func TestAWS_Apply_FallsBackToOperatorDefault(t *testing.T) {
	operatorDefault := &recordingAWSWriter{}
	a := &AWS{
		Writer:          operatorDefault,
		WriterForConfig: func(_, _ string) AWSWriter { t.Fatal("per-tenant factory must not fire without config"); return nil },
	}
	conn := platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnAWS} // no Config
	act := platform.Action{ID: "act", Payload: map[string]any{"remediation_type": "s3_block_public_access", "target": "my-bucket"}}
	if err := a.Apply(context.Background(), conn, "", act); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if operatorDefault.blocked != "my-bucket" {
		t.Errorf("operator default should have blocked my-bucket, got %q", operatorDefault.blocked)
	}
}

// No operator default AND no per-tenant config → an honest "not configured" error, never a false ok.
func TestAWS_Apply_NoWriterIsHonestError(t *testing.T) {
	a := &AWS{} // no Writer, no factory
	conn := platform.Connection{ID: "c1", Kind: platform.ConnAWS}
	act := platform.Action{ID: "act", Payload: map[string]any{"remediation_type": "s3_block_public_access", "target": "b"}}
	if err := a.Apply(context.Background(), conn, "", act); err == nil {
		t.Error("apply with no write path must error, not silently succeed")
	}
}

type recordingGCPWriter struct{ project, bucket string }

func (r *recordingGCPWriter) EnforceBucketPublicAccessPrevention(_ context.Context, project, bucket string) error {
	r.project, r.bucket = project, bucket
	return nil
}

func TestGCP_Apply_UsesPerTenantWriterFromConfig(t *testing.T) {
	perTenant := &recordingGCPWriter{}
	var gotSA string
	g := &GCP{WriterForConfig: func(sa string) GCPWriter { gotSA = sa; return perTenant }}
	conn := platform.Connection{ID: "c1", Kind: platform.ConnGCP, Account: "proj-1", Config: map[string]string{
		platform.CfgRemediationEnabled: "true",
		platform.CfgRemediationSA:      "remediate@proj-1.iam.gserviceaccount.com",
	}}
	act := platform.Action{ID: "act", Payload: map[string]any{"remediation_type": "gcs_public_access_prevention", "target": "gs://my-bkt"}}
	if err := g.Apply(context.Background(), conn, "", act); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if perTenant.bucket != "my-bkt" || perTenant.project != "proj-1" {
		t.Errorf("per-tenant GCP writer wrong project/bucket: %q / %q", perTenant.project, perTenant.bucket)
	}
	if gotSA != "remediate@proj-1.iam.gserviceaccount.com" {
		t.Errorf("factory got wrong SA: %q", gotSA)
	}
}

type recordingAzureWriter struct{ sub, rg, account string }

func (r *recordingAzureWriter) DisableStoragePublicAccess(_ context.Context, sub, rg, account string) error {
	r.sub, r.rg, r.account = sub, rg, account
	return nil
}

func TestAzure_Apply_UsesPerTenantWriterWhenEnabled(t *testing.T) {
	perTenant := &recordingAzureWriter{}
	called := 0
	z := &Azure{WriterForConfig: func() AzureWriter { called++; return perTenant }}
	conn := platform.Connection{ID: "c1", Kind: platform.ConnAzure, Account: "sub-123", Config: map[string]string{
		platform.CfgRemediationEnabled: "true",
	}}
	act := platform.Action{ID: "act", Payload: map[string]any{"remediation_type": "azure_storage_disable_public_access", "target": "myrg/myacct"}}
	if err := z.Apply(context.Background(), conn, "", act); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if called != 1 || perTenant.sub != "sub-123" || perTenant.account != "myacct" {
		t.Errorf("per-tenant Azure writer not used correctly: called=%d %+v", called, perTenant)
	}
}
