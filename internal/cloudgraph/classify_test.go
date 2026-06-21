package cloudgraph

import "testing"

func TestIsDataStoreType_MultiCloud(t *testing.T) {
	stores := []string{
		"AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::DynamoDB::Table", // AWS
		"storage.googleapis.com/Bucket", "bigquery.googleapis.com/Dataset", "spanner.googleapis.com/Instance", // GCP
		"Microsoft.Storage/storageAccounts/blobServices", "Microsoft.DocumentDB/databaseAccounts", "Microsoft.Sql/servers/databases", // Azure
	}
	for _, s := range stores {
		if !IsDataStoreType(s) {
			t.Errorf("%q should classify as a data store", s)
		}
	}
	notStores := []string{"AWS::IAM::Role", "compute.googleapis.com/Instance", "Microsoft.Network/virtualNetworks"}
	for _, s := range notStores {
		if IsDataStoreType(s) {
			t.Errorf("%q should NOT be a data store", s)
		}
	}
}

func TestComputeKind_MultiCloud(t *testing.T) {
	cases := map[string]string{
		"AWS::ECS::TaskDefinition":                    "ECS",
		"AWS::EKS::Cluster":                           "EKS",
		"AWS::Lambda::Function":                       "Lambda",
		"run.googleapis.com/Service":                  "CloudRun",
		"container.googleapis.com/Cluster":            "GKE",
		"Microsoft.ContainerService/managedClusters":  "AKS",
		"Microsoft.ContainerInstance/containerGroups": "ACI",
	}
	for typ, want := range cases {
		if got := ComputeKind(typ); got != want {
			t.Errorf("ComputeKind(%q) = %q, want %q", typ, got, want)
		}
	}
	if !IsComputeType("run.googleapis.com/Service") || IsComputeType("AWS::S3::Bucket") {
		t.Error("IsComputeType misclassified")
	}
}
