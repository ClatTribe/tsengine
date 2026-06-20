package cloudtocode

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// CloudFinding is the cloud side of a Cloud-to-Code link: a runtime
// misconfiguration with the identifiers needed to find its IaC source.
type CloudFinding struct {
	CheckID  string // prowler check id, e.g. "s3_bucket_level_public_access_block"
	Resource string // physical resource name, e.g. "acme-prod-assets"
	ARN      string // resource UID / ARN, if known
	Type     string // OCSF/cloud resource type, e.g. "AwsS3Bucket" (fallback service hint)
}

// serviceToTFTypes maps a coarse cloud-service token (the prowler check-id
// prefix) to the Terraform resource types that provision that service. The type
// nexus is the guard against a cloud resource name coincidentally matching an
// unrelated resource elsewhere in the tree — a link requires BOTH a shared
// identifier and a plausible type. AWS-focused (the dominant prowler+Terraform
// pairing); GCP/Azure prefixes extend this table.
var serviceToTFTypes = map[string][]string{
	"s3":             {"aws_s3_bucket"},
	"ec2":            {"aws_instance", "aws_security_group", "aws_ebs_volume", "aws_eip", "aws_network_acl", "aws_default_security_group"},
	"vpc":            {"aws_vpc", "aws_subnet", "aws_security_group", "aws_network_acl", "aws_default_vpc"},
	"iam":            {"aws_iam_role", "aws_iam_user", "aws_iam_policy", "aws_iam_group", "aws_iam_access_key", "aws_iam_role_policy"},
	"rds":            {"aws_db_instance", "aws_rds_cluster", "aws_db_cluster", "aws_rds_cluster_instance"},
	"lambda":         {"aws_lambda_function"},
	"cloudtrail":     {"aws_cloudtrail"},
	"kms":            {"aws_kms_key"},
	"sqs":            {"aws_sqs_queue"},
	"sns":            {"aws_sns_topic"},
	"dynamodb":       {"aws_dynamodb_table"},
	"elb":            {"aws_lb", "aws_elb", "aws_alb", "aws_lb_listener"},
	"elbv2":          {"aws_lb", "aws_alb", "aws_lb_listener"},
	"efs":            {"aws_efs_file_system"},
	"ecr":            {"aws_ecr_repository"},
	"eks":            {"aws_eks_cluster"},
	"ecs":            {"aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition"},
	"redshift":       {"aws_redshift_cluster"},
	"cloudfront":     {"aws_cloudfront_distribution"},
	"apigateway":     {"aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_api_gateway_stage"},
	"apigatewayv2":   {"aws_apigatewayv2_api", "aws_apigatewayv2_stage"},
	"secretsmanager": {"aws_secretsmanager_secret"},
	"elasticache":    {"aws_elasticache_cluster", "aws_elasticache_replication_group"},
	"cloudwatch":     {"aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm"},
	"opensearch":     {"aws_opensearch_domain", "aws_elasticsearch_domain"},
	"elasticsearch":  {"aws_elasticsearch_domain", "aws_opensearch_domain"},
}

// serviceOf derives the coarse service token. The prowler check-id prefix (the
// segment before the first underscore) is the reliable signal; the OCSF type is
// a fallback when no check id is present.
func serviceOf(checkID, ocsfType string) string {
	if checkID != "" {
		if i := strings.IndexByte(checkID, '_'); i > 0 {
			return strings.ToLower(checkID[:i])
		}
		return strings.ToLower(checkID)
	}
	// Fallback: scan the OCSF type for a known service token (e.g. "AwsS3Bucket").
	lt := strings.ToLower(ocsfType)
	for svc := range serviceToTFTypes {
		if strings.Contains(lt, svc) {
			return svc
		}
	}
	return ""
}

// match finds the best IaC source for a cloud finding, or nil if there is no
// grounded link. "Best" = a high-confidence physical/ARN identifier match over
// a medium-confidence logical-name match; ties broken deterministically by
// (file, line).
func match(cf CloudFinding, idx []Resource) *types.CodeProvenance {
	svc := serviceOf(cf.CheckID, cf.Type)
	if svc == "" {
		return nil
	}
	tfTypes := serviceToTFTypes[svc]
	if len(tfTypes) == 0 {
		return nil
	}
	typeSet := map[string]bool{}
	for _, t := range tfTypes {
		typeSet[t] = true
	}

	// Tokens from the cloud finding that could appear in source. Short tokens
	// are dropped — a 2-char name would match noise.
	var cloudTokens []string
	for _, t := range []string{strings.TrimSpace(cf.Resource), arnTail(cf.ARN)} {
		if len(t) >= 3 {
			cloudTokens = appendUnique(cloudTokens, t)
		}
	}
	if len(cloudTokens) == 0 {
		return nil
	}

	// Stable iteration: sort candidate resources by (file, line).
	cands := make([]Resource, 0, len(idx))
	for _, r := range idx {
		if typeSet[r.Type] {
			cands = append(cands, r)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].File != cands[j].File {
			return cands[i].File < cands[j].File
		}
		return cands[i].Line < cands[j].Line
	})

	var medium *types.CodeProvenance
	for _, r := range cands {
		for _, ct := range cloudTokens {
			// HIGH: an exact (case-insensitive) literal token shared between the
			// cloud resource and the IaC block — the physical name, a tag value,
			// or the ARN tail appears verbatim in source.
			for _, id := range r.Identifiers {
				if strings.EqualFold(id, ct) {
					return &types.CodeProvenance{
						File:        r.File,
						Line:        r.Line,
						IaCResource: r.Address(),
						MatchedOn:   ct,
						MatchBasis:  "cloud resource name found verbatim in the IaC block",
						Confidence:  "high",
					}
				}
			}
			// MEDIUM (held, not returned yet): the block's logical name is the
			// cloud name with separators normalized — the developer named the
			// block after the resource, but the physical name is computed.
			if medium == nil && normalizeID(r.LogicalName) == normalizeID(ct) {
				medium = &types.CodeProvenance{
					File:        r.File,
					Line:        r.Line,
					IaCResource: r.Address(),
					MatchedOn:   ct,
					MatchBasis:  "IaC resource logical name matches the cloud resource name (normalized)",
					Confidence:  "medium",
				}
			}
		}
	}
	return medium
}

// arnTail returns the last segment of an ARN/UID (the resource name part),
// e.g. "arn:aws:s3:::acme-prod-assets" → "acme-prod-assets".
func arnTail(arn string) string {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return ""
	}
	if i := strings.LastIndexAny(arn, ":/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

// normalizeID lowercases and removes `-`/`_` so "acme-prod-assets" and
// "acme_prod_assets" compare equal (Terraform logical names can't contain
// dashes; physical names usually do).
func normalizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
