// Package awsfetch reads a customer's live AWS state through a scoped, read-only cross-account role.
//
// WHY THIS EXISTS. Until now the cloud picture arrived only by someone POSTing an inventory, so its
// freshness was bounded by when a human last remembered to. The AI Cloud Engineer reasoned over
// whatever that snapshot said, however old (see platformapi.snapshotAgeNote). Fetching it ourselves is
// what turns a snapshot analyser into something that can answer "what does my account look like NOW".
//
// The SDK lives here and not in package connector, which stays SDK-free — the same isolation
// awsremediate uses for the write path.
//
// # A PARTIAL INVENTORY IS THE DANGEROUS CASE
//
// This fetches OBJECT STORAGE today. IAM, EC2 and security groups are the next increment and need
// SDK modules that are not vendored yet.
//
// That matters more than it sounds. cloudgraph builds attack paths out of principals, trust edges and
// network reach; an inventory with buckets and no principals cannot form a path, so an agent reasoning
// over it would find none and could report an account as clean when nothing about its identity layer
// was ever examined. That is the same false all-clear this codebase keeps having to remove, and a
// fetcher is a particularly bad place to introduce it because the result LOOKS live.
//
// So Result carries Sources — exactly what was read — and callers are expected to surface it. An
// inventory that cannot say what it covered has no business being reasoned over.
package awsfetch

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

// Result is a fetched inventory plus an honest statement of what it covers.
type Result struct {
	Raw awsinventory.RawAWS
	// Sources are the AWS surfaces actually read ("s3"). Anything absent was NOT examined — not
	// examined and found clean, which is a different fact.
	Sources []string
	// Skipped explains, per surface, why it was not read. Present so a caller can tell "we have no
	// IAM support yet" from "the role could not list IAM".
	Skipped map[string]string
}

// Covers reports whether a surface was actually read.
func (r Result) Covers(surface string) bool {
	for _, s := range r.Sources {
		if s == surface {
			return true
		}
	}
	return false
}

// Coverage renders the honest one-liner a caller should show next to any conclusion drawn from this
// inventory. Never empty: silence about coverage is how a partial picture passes for a whole one.
func (r Result) Coverage() string {
	if len(r.Sources) == 0 {
		return "No AWS surface was read — this inventory states nothing about the account."
	}
	var missing []string
	for k := range r.Skipped {
		missing = append(missing, k)
	}
	sort.Strings(missing)
	s := "Read: " + strings.Join(r.Sources, ", ") + "."
	if len(missing) > 0 {
		s += " NOT read: " + strings.Join(missing, ", ") +
			" — attack paths through those surfaces cannot be seen in this inventory."
	}
	return s
}

// BucketLister is the S3 surface this needs. An interface so the fetch logic is testable without
// credentials, and so the SDK stays swappable — the same shape awsremediate uses.
type BucketLister interface {
	ListBuckets(ctx context.Context) ([]Bucket, error)
}

// Bucket is one object store as the lister reports it.
type Bucket struct {
	Name      string
	Region    string
	Public    bool // resolved from the public-access-block / ACL by the lister
	Sensitive bool // resolved from tags by the lister
}

// Fetcher reads live account state. A nil BucketLister is not an empty account — see Fetch.
type Fetcher struct {
	AccountID string
	Buckets   BucketLister
	// Principals reads the identity layer. Without it an inventory has no principals and no trust
	// edges, so cloudgraph cannot form an attack path — see the package comment on why that is the
	// dangerous kind of partial.
	Principals IAMReader
}

// Fetch reads what it can and reports exactly that.
//
// IT REFUSES RATHER THAN INVENTS. With no lister wired there are no credentials, and returning an
// empty RawAWS would be indistinguishable from an account with no buckets — a clean bill of health
// nobody earned. That returns an error instead.
//
// A per-surface failure is recorded in Skipped and does not fail the whole fetch: reading buckets but
// not IAM is a useful partial answer as long as it says so, which Coverage does.
func (f Fetcher) Fetch(ctx context.Context) (Result, error) {
	if f.Buckets == nil {
		return Result{}, fmt.Errorf("awsfetch: no AWS access configured — cannot read the account " +
			"(an empty inventory would read as an account with nothing in it)")
	}
	res := Result{
		Raw:     awsinventory.RawAWS{AccountID: f.AccountID},
		Skipped: map[string]string{},
	}

	bs, err := f.Buckets.ListBuckets(ctx)
	if err != nil {
		// Say which surface failed and why; do not silently produce an inventory without it.
		res.Skipped["s3"] = err.Error()
	} else {
		for _, b := range bs {
			res.Raw.Buckets = append(res.Raw.Buckets, awsinventory.RawBucket{
				Name: b.Name, Region: b.Region, Public: b.Public, Sensitive: b.Sensitive,
			})
		}
		res.Sources = append(res.Sources, "s3")
	}

	if f.Principals == nil {
		res.Skipped["iam"] = "no identity reader configured — principals and trust policies are unread"
	} else if ps, ierr := f.Principals.ListPrincipals(ctx); ierr != nil {
		res.Skipped["iam"] = ierr.Error()
	} else {
		for _, p := range ps {
			if p.Role {
				res.Raw.Roles = append(res.Raw.Roles, awsinventory.RawIAMRole{
					ARN: p.ARN, Name: p.Name, Admin: p.Admin, TrustPolicyJSON: p.Trust,
				})
				continue
			}
			res.Raw.Users = append(res.Raw.Users, awsinventory.RawIAMUser{
				ARN: p.ARN, Name: p.Name, Admin: p.Admin,
			})
		}
		res.Sources = append(res.Sources, "iam")
	}

	// Still unimplemented. Named explicitly so a caller can never mistake its absence for an account
	// that has no compute.
	res.Skipped["ec2"] = "not implemented yet — instances and security groups are unread"

	if len(res.Sources) == 0 {
		return res, fmt.Errorf("awsfetch: every surface failed: %v", res.Skipped)
	}
	return res, nil
}
