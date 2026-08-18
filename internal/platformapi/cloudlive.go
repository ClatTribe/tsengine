package platformapi

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
)

// cloudlive.go adapts the platform's already-wired read-only AWS fetcher into the SDK-free
// cloudagent.LiveReader the agent talks to. The agent asks per-resource questions; this answers them
// from ONE live read of the account, cached for the investigation.
//
// Why one read rather than a call per question: the fetcher's readers are surface listers, so a
// naive per-resource implementation would re-list the whole account for every question the agent
// asks — slow, rate-limited, and expensive on a large estate. Reading once and serving many
// questions from it keeps the live capability affordable, which is what makes it safe to leave on.
//
// The read is READ-ONLY by construction: awsfetch issues only describe/list verbs, and the role is
// assumed with cloudsafety.SessionPolicy(), which denies mutation outright. This adapter adds no
// write path and cannot.

// liveReaderOrNil builds the agent's live re-read capability for a tenant, or returns nil when this
// deployment has no live AWS path (no fetcher wired, or the tenant has not connected an account).
//
// Nil is a first-class answer, not a failure: check_live then tells the agent the snapshot is
// unconfirmed rather than letting it assume the snapshot is current (§10). Resolving the connection
// here — before any tool call — keeps the agent's first live question fast.
func (d Deps) liveReaderOrNil(ctx context.Context, tenantID string) cloudagent.LiveReader {
	if d.AWSFetcher == nil {
		return nil
	}
	conn, err := d.awsConnection(ctx, tenantID)
	if err != nil {
		return nil // no connected account — most tenants
	}
	return newLiveReader(func(c context.Context) (awsfetch.Result, error) {
		return d.AWSFetcher(conn).Fetch(c)
	})
}

// liveReader serves cloudagent's live re-reads from a single cached fetch.
type liveReader struct {
	fetch func(context.Context) (awsfetch.Result, error)

	once   sync.Once
	res    awsfetch.Result
	err    error
	readAt time.Time
}

// newLiveReader builds the adapter. fetch is called at most once, lazily — an investigation that
// never asks a live question costs nothing.
func newLiveReader(fetch func(context.Context) (awsfetch.Result, error)) *liveReader {
	return &liveReader{fetch: fetch}
}

func (l *liveReader) load(ctx context.Context) (awsfetch.Result, error) {
	l.once.Do(func() {
		l.res, l.err = l.fetch(ctx)
		l.readAt = time.Now().UTC()
	})
	return l.res, l.err
}

// Coverage reports what the live read covered — reused verbatim from awsfetch, which already states
// what was NOT read and why that limits conclusions.
func (l *liveReader) Coverage() string {
	if l.err != nil {
		return "The live read failed, so nothing about the account was confirmed."
	}
	if l.readAt.IsZero() {
		return "No live read has been performed yet."
	}
	return l.res.Coverage()
}

// CheckLive answers one per-resource question from the cached live read.
//
// The load-bearing decision is which surface an id belongs to, because that decides whether "absent"
// means DELETED or merely UNREAD. An id whose surface was skipped comes back Covered:false with the
// reason — never Found:false, which the agent would (correctly) read as "it is gone".
func (l *liveReader) CheckLive(ctx context.Context, id string) (cloudagent.LiveFact, error) {
	res, err := l.load(ctx)
	if err != nil {
		return cloudagent.LiveFact{}, err
	}
	at := l.readAt.Format(time.RFC3339)
	surface := surfaceOf(id)
	if surface == "" {
		return cloudagent.LiveFact{
			Covered: false, ReadAt: at,
			Why: fmt.Sprintf("%q is not an id this live reader knows how to look up (it reads s3, iam and ec2)", id),
		}, nil
	}
	if !res.Covers(surface) {
		why := res.Skipped[surface]
		if why == "" {
			why = "the " + surface + " surface was not read"
		}
		return cloudagent.LiveFact{Covered: false, ReadAt: at, Why: why}, nil
	}

	fact := cloudagent.LiveFact{Covered: true, ReadAt: at}
	switch surface {
	case "s3":
		for _, b := range res.Raw.Buckets {
			if !sameResource(b.ARN, b.Name, id) {
				continue
			}
			fact.Found, fact.Public, fact.Sensitive = true, b.Public, b.Sensitive
			if b.Public {
				fact.Detail = "bucket is public right now"
			}
			return fact, nil
		}
	case "iam":
		for _, r := range res.Raw.Roles {
			if !sameResource(r.ARN, r.Name, id) {
				continue
			}
			fact.Found, fact.Privileged = true, r.Admin
			if r.Admin {
				fact.Detail = "role currently holds admin-level permissions"
			}
			return fact, nil
		}
		for _, u := range res.Raw.Users {
			if !sameResource(u.ARN, u.Name, id) {
				continue
			}
			fact.Found, fact.Privileged = true, u.Admin
			if u.Admin {
				fact.Detail = "user currently holds admin-level permissions"
			}
			return fact, nil
		}
	case "ec2":
		for _, i := range res.Raw.Instances {
			// Instances carry an instance id, not an ARN, so the id the agent holds ("…:instance/i-web")
			// matches on its trailing segment.
			if !sameResource("", i.ID, id) {
				continue
			}
			fact.Found, fact.Public = true, i.PublicIP
			if i.PublicIP {
				fact.Detail = "instance is internet-facing right now"
				if i.ServicePort > 0 {
					fact.Detail += fmt.Sprintf(" (service port %d)", i.ServicePort)
				}
			}
			return fact, nil
		}
	}
	// The surface WAS read and the resource is not in it — a real, citable absence.
	return fact, nil
}

// surfaceOf maps a resource id to the awsfetch surface that would have read it. "" when the id is
// not one this reader covers, which is reported as not-covered rather than not-found.
func surfaceOf(id string) string {
	switch {
	case strings.HasPrefix(id, "arn:aws:s3:"):
		return "s3"
	case strings.HasPrefix(id, "arn:aws:iam:"):
		return "iam"
	case strings.HasPrefix(id, "arn:aws:ec2:"):
		return "ec2"
	}
	return ""
}

// sameResource matches a live resource against the id the agent asked about, accepting either the
// full ARN or the bare name/id — graphs and inventories disagree about which they carry, and a
// mismatch here would silently report a live resource as deleted.
func sameResource(arn, name, want string) bool {
	if want == "" {
		return false
	}
	if arn != "" && strings.EqualFold(arn, want) {
		return true
	}
	if name != "" && strings.EqualFold(name, want) {
		return true
	}
	// An ARN's trailing segment is the resource name ("arn:aws:s3:::bucket", ".../role/app").
	if i := strings.LastIndexAny(want, ":/"); i >= 0 && i+1 < len(want) && name != "" {
		return strings.EqualFold(name, want[i+1:])
	}
	return false
}
