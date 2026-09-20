package awsfetch

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// DatabaseReader reads the account's RDS instances: the data stores an attack path ends at. Public
// accessibility, the listening port and the security groups are what decide whether the internet
// can actually reach one (the same CIDR-coverage test instances get, never "it has a public DNS
// name"); encryption at rest is the posture fact; sensitivity comes from the customer's own tags,
// as it does for buckets, and is never inferred from an engine name.
type DatabaseReader interface {
	ListDatabases(ctx context.Context) ([]Database, error)
}

// Database is one RDS instance as the lister reports it.
type Database struct {
	ARN       string
	ID        string
	Region    string
	Engine    string
	Public    bool // PubliclyAccessible — a public endpoint exists; reachability still needs an open SG
	Encrypted bool
	Port      int
	SGIDs     []string
	Sensitive bool // from tags, the way buckets are
}

type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// RDSLister reads through the connected read-only role (rds:DescribeDBInstances is a READ).
type RDSLister struct {
	Region     string
	RoleARN    string
	ExternalID string

	api rdsAPI // injected in tests
}

func NewRDSLister(region, roleARN, externalID string) *RDSLister {
	return &RDSLister{Region: region, RoleARN: roleARN, ExternalID: externalID}
}

func (l *RDSLister) client(ctx context.Context) (rdsAPI, error) {
	if l.api != nil {
		return l.api, nil
	}
	cfg, err := assumeRoleConfig(ctx, l.Region, l.RoleARN, l.ExternalID)
	if err != nil {
		return nil, err
	}
	return rds.NewFromConfig(cfg), nil
}

func (l *RDSLister) ListDatabases(ctx context.Context) ([]Database, error) {
	api, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	var out []Database
	var marker *string
	for {
		res, err := api.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("awsfetch: describe db instances: %w", err)
		}
		for _, db := range res.DBInstances {
			d := Database{
				ARN: aws.ToString(db.DBInstanceArn), ID: aws.ToString(db.DBInstanceIdentifier), Region: l.Region,
				Engine: aws.ToString(db.Engine), Public: aws.ToBool(db.PubliclyAccessible), Encrypted: aws.ToBool(db.StorageEncrypted),
			}
			if db.Endpoint != nil {
				d.Port = int(aws.ToInt32(db.Endpoint.Port))
			}
			for _, sg := range db.VpcSecurityGroups {
				if id := aws.ToString(sg.VpcSecurityGroupId); id != "" {
					d.SGIDs = append(d.SGIDs, id)
				}
			}
			for _, t := range db.TagList {
				if sensitiveTag(aws.ToString(t.Key), aws.ToString(t.Value)) {
					d.Sensitive = true
				}
			}
			out = append(out, d)
		}
		if res.Marker == nil || aws.ToString(res.Marker) == "" {
			break
		}
		marker = res.Marker
	}
	return out, nil
}

// sensitiveTag is the same declared-sensitivity convention the S3 lister honours: a tag that says
// the store holds regulated data. Declared by the customer, never inferred.
func sensitiveTag(k, v string) bool {
	k, v = strings.ToLower(strings.TrimSpace(k)), strings.ToLower(strings.TrimSpace(v))
	switch k {
	case "sensitivity", "data-classification", "dataclassification", "classification", "data_classification":
		return v == "high" || v == "pii" || v == "phi" || v == "pci" || v == "confidential" || v == "restricted" || v == "sensitive"
	case "pii", "phi", "pci", "sensitive":
		return v == "true" || v == "yes" || v == "1"
	}
	return false
}
