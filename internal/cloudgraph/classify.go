package cloudgraph

import "strings"

// Provider-aware resource classification (ADR 0009 Phase 4 — multi-cloud reasoning). The
// reasoning core (FindPaths, the attack-edge set, the jewel predicate) is already
// provider-agnostic: it runs over the NORMALIZED graph, not over AWS-specific shapes. What was
// AWS-shaped was the resource-TYPE recognition the DSPM (data store) and CWPP (compute/workload)
// lenses used. These helpers classify a resource type across AWS / GCP / Azure so those lenses
// fire on all three providers — e.g. a public GCS bucket or Azure Blob is a DSPM exposure, a
// public Cloud Run / AKS workload is a CWPP target. Case-insensitive substring match on the
// normalized type string (CAI / ARM / CloudFormation forms all covered).

var dataStoreKeywords = []string{
	// AWS
	"s3", "rds", "dynamodb", "efs", "redshift", "elasticache", "documentdb", "fsx",
	// GCP
	"storage", "bucket", "bigquery", "spanner", "datastore", "firestore", "bigtable", "filestore", "cloudsql", "sqladmin",
	// Azure
	"blob", "cosmos", "sqlserver", "sqldatabase", "datalake", "synapse", "tablestorage",
	// generic
	"database", "datawarehouse",
}

// IsDataStoreType reports whether a resource type holds data worth a DSPM verdict, across
// AWS / GCP / Azure.
func IsDataStoreType(typ string) bool {
	t := strings.ToLower(typ)
	for _, kw := range dataStoreKeywords {
		if strings.Contains(t, kw) {
			return true
		}
	}
	return false
}

// computeKindRules maps a type substring → a short workload-kind label, first match wins.
// Ordered most-specific-first so e.g. "eks" beats the generic "ec2"/"compute".
var computeKindRules = []struct{ kw, label string }{
	// AWS
	{"lambda", "Lambda"}, {"fargate", "Fargate"}, {"::ecs::", "ECS"}, {"::eks::", "EKS"},
	{"::ec2::", "EC2"},
	// GCP
	{"run.googleapis", "CloudRun"}, {"cloudrun", "CloudRun"}, {"container.googleapis", "GKE"},
	{"gke", "GKE"}, {"cloudfunctions", "CloudFunction"}, {"compute.googleapis", "GCE"},
	// Azure
	{"containerservice", "AKS"}, {"managedclusters", "AKS"}, {"aks", "AKS"},
	{"containerinstance", "ACI"}, {"virtualmachines", "VM"}, {"microsoft.web", "AppService"},
	{"appservice", "AppService"},
	// generic
	{"function", "Function"}, {"instance", "Instance"}, {"container", "Container"},
}

// ComputeKind returns a short, provider-normalized workload-kind label (ECS, GKE, AKS,
// CloudRun, Lambda, VM, …). Best-effort; falls back to the last type segment when unknown.
func ComputeKind(typ string) string {
	t := strings.ToLower(typ)
	for _, r := range computeKindRules {
		if strings.Contains(t, r.kw) {
			return r.label
		}
	}
	// Fall back to the last segment after the provider's separator (::, /, or .).
	seg := typ
	for _, sep := range []string{"::", "/", "."} {
		if i := strings.LastIndex(seg, sep); i >= 0 {
			seg = seg[i+len(sep):]
		}
	}
	return seg
}

// IsComputeType reports whether a type is a compute/workload across the three providers.
func IsComputeType(typ string) bool {
	t := strings.ToLower(typ)
	for _, r := range computeKindRules {
		if strings.Contains(t, r.kw) {
			return true
		}
	}
	return false
}
