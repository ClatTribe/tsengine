// Package productscope proposes which of a tenant's assets make up each PRODUCT their customers buy
// and review — the scoping unit of CTEM (ADR 0028 G2), stated in the terms the buyer actually uses.
//
// # Why "product", and why proposed-then-confirmed
//
// For a company without a security team, CTEM's "business service" is the same act as the scope of a
// customer's security review: the system a pentest report covers, the boundary of the trust centre,
// the system description in SOC 2. So the unit is the product, and the question a reviewer asks —
// "does this report cover what we are buying?" — is answered by it.
//
// A free-text tag nobody maintains is worse than no scope at all, because a stale map reads as scope
// (ADR 0028). So the platform PROPOSES, from links it can prove, and a named human CONFIRMS. Nothing
// here stores anything: proposals are recomputed on every read, so they cannot go stale on disk.
//
// # The links, and the ones deliberately NOT used (§10 — exact, never resemblance)
//
//   - shared_domain: web, api and domain assets whose hosts sit under the same REGISTERED domain
//     (public-suffix eTLD+1). A DNS ownership fact, not a name match — and the public-suffix list's
//     private section keeps foo.vercel.app and bar.vercel.app apart, so two strangers on the same
//     host platform are never joined.
//   - ci_deploys_to: a GitHub repository whose Actions workflows can assume a role in a connected cloud
//     account (the estate graph's ghoidc `assumes` edge). "This code deploys into this account."
//
// NOT used, each for a reason worth keeping: the internet pseudo-node and network nodes (every public
// asset would join every other through them); human identities (a CTO who can reach every repository
// would merge the whole estate into one product); leaked credentials (a key found in a repo may belong
// to a third party's account, and a vulnerability is not a deployment relationship); and ANY name
// similarity between a repo, an image and a host. An asset no proven link reaches is left UNASSIGNED
// for a human to place — that list is the honest answer, not a gap to paper over.
package productscope

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// LinkKind names why two assets were grouped.
type LinkKind string

const (
	LinkSharedDomain LinkKind = "shared_domain"
	LinkCIDeploysTo  LinkKind = "ci_deploys_to"
)

// Link is a proven relationship between two assets. A is always the lexically smaller id.
type Link struct {
	A        string   `json:"a"`
	B        string   `json:"b"`
	Kind     LinkKind `json:"kind"`
	Why      string   `json:"why"`
	Evidence []string `json:"evidence"`
}

// Proposal is a candidate product: assets joined by proven links, awaiting a named human.
type Proposal struct {
	Name     string   `json:"name"`
	AssetIDs []string `json:"asset_ids"`
	Links    []Link   `json:"links"`
}

// Suggestion is an unassigned asset with a proven link into an already-confirmed product. It is
// SUGGESTED, never added: a confirmed scope changes only when a human changes it.
type Suggestion struct {
	ProductID string `json:"product_id"`
	AssetID   string `json:"asset_id"`
	Link      Link   `json:"link"`
}

// Group is a set of unassigned assets joined by proven links (or a single asset with none).
type Group struct {
	AssetIDs []string `json:"asset_ids"`
	Links    []Link   `json:"links"`
}

// Result is the full scoping picture for one read.
type Result struct {
	Proposals   []Proposal   `json:"proposals"`
	Suggestions []Suggestion `json:"suggestions"`
	// Unassigned are in-scope assets in no product, no proposal and no suggestion, kept in the groups
	// their proven links form. A multi-asset group is infrastructure we can PROVE belongs together
	// (a repo that deploys into an account) but cannot tie to a product — reported as a group so a
	// human places it in one step, and never proposed as a product of its own, which would tell a
	// founder they run two products when the second is almost certainly the first one's backend.
	Unassigned []Group `json:"unassigned"`
}

// customerFacing reports whether an asset is something a customer reaches — the surface a product
// is identified by. A lone repository or cloud account is infrastructure BEHIND a product; it is not
// proposed as a product by itself.
func customerFacing(a platform.Asset) bool {
	switch a.Type {
	case "web_application", "api", "domain":
		return true
	}
	return false
}

// Links derives every proven link among the assets. g may be nil (no estate composed): the domain
// links still hold, the CI links are simply absent — and the caller says so rather than implying
// the estate had no deploy relationships.
func Links(assets []platform.Asset, g *estategraph.Graph) []Link {
	var out []Link

	// shared_domain — group customer-facing assets by registered domain, link each to the group's
	// first member (a star keeps it connected without O(n²) links).
	byDomain := map[string][]platform.Asset{}
	for _, a := range sortedAssets(assets) {
		if !customerFacing(a) {
			continue
		}
		if d := RegisteredDomain(a.Target); d != "" {
			byDomain[d] = append(byDomain[d], a)
		}
	}
	for d, group := range byDomain {
		for _, other := range group[1:] {
			out = append(out, newLink(group[0].ID, other.ID, LinkSharedDomain,
				hostOf(group[0].Target)+" and "+hostOf(other.Target)+" are both under the registered domain "+d,
				[]string{"registered-domain:" + d}))
		}
	}

	// ci_deploys_to — one hop, code → cloud principal, and only the `assumes` kind.
	if g != nil {
		repoByNode := map[string]string{} // estate code node id → repository asset id
		accountAssets := map[string]string{}
		for _, a := range assets {
			switch a.Type {
			case "repository":
				if key := GitHubRepoNode(a.Target); key != "" {
					repoByNode[key] = a.ID
				}
			case "cloud_account":
				for _, k := range []string{"account_id", "project_id", "subscription_id"} {
					if v := strings.ToLower(strings.TrimSpace(a.Meta[k])); v != "" {
						accountAssets[v] = a.ID
					}
				}
			}
		}
		for _, e := range g.Edges {
			if e.Kind != estategraph.EdgeAssumes || len(e.Evidence) == 0 {
				continue
			}
			repoID, ok := repoByNode[e.From]
			if !ok {
				continue
			}
			acct := AccountOfPrincipal(e.To)
			cloudID, ok := accountAssets[acct]
			if !ok || acct == "" {
				continue // the role is in an account this tenant has not connected — no asset to join
			}
			why := "a GitHub Actions workflow in " + strings.TrimPrefix(e.From, "code:") +
				" can assume " + strings.TrimPrefix(e.To, "cloud:") + " in " + acct
			if strings.TrimSpace(e.Why) != "" {
				why += " (" + e.Why + ")"
			}
			out = append(out, newLink(repoID, cloudID, LinkCIDeploysTo, why, append([]string(nil), e.Evidence...)))
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].A != out[j].A {
			return out[i].A < out[j].A
		}
		if out[i].B != out[j].B {
			return out[i].B < out[j].B
		}
		return out[i].Kind < out[j].Kind
	})
	return dedupeLinks(out)
}

// Propose turns links into proposals, suggestions and the unassigned remainder, given what a human
// has already confirmed and excluded.
//
// "Belongs with" is TRANSITIVE over proven links — sharing a registered domain is an equivalence, and a
// repo that deploys into an account is with whatever that account is with. So groups are built over ALL
// in-scope assets, confirmed members included. A group that touches a confirmed product turns every
// free asset in it into a SUGGESTION for that product; only a group touching no product becomes a
// proposal. Checking direct links alone was a real bug: with a product holding app.acme.com, the star
// of domain links could leave www.acme.com one hop away, and it was then proposed as a SECOND product
// named after the same domain the first one already carries.
func Propose(assets []platform.Asset, links []Link, products []platform.Product, out map[string]platform.ScopeExclusion) Result {
	res := Result{Proposals: []Proposal{}, Suggestions: []Suggestion{}, Unassigned: []Group{}}

	byID := map[string]platform.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}
	inScope := func(id string) bool { _, ex := out[id]; _, ok := byID[id]; return ok && !ex }
	memberOf := map[string][]string{} // asset id → product ids (existing assets only)
	for _, p := range products {
		for _, id := range p.AssetIDs {
			if _, ok := byID[id]; ok {
				memberOf[id] = append(memberOf[id], p.ID)
			}
		}
	}

	// Union-find over every in-scope asset and every link whose ends are both in scope.
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == x {
			return x
		}
		parent[x] = find(parent[x])
		return parent[x]
	}
	for _, a := range assets {
		if inScope(a.ID) {
			parent[a.ID] = a.ID
		}
	}
	var scoped []Link
	for _, l := range links {
		if !inScope(l.A) || !inScope(l.B) {
			continue
		}
		scoped = append(scoped, l)
		ra, rb := find(l.A), find(l.B)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	}
	comps := map[string][]string{}
	for id := range parent {
		r := find(id)
		comps[r] = append(comps[r], id)
	}

	for _, members := range comps {
		sort.Strings(members)
		in := map[string]bool{}
		products := map[string]bool{}
		var free []string
		facing := false
		for _, id := range members {
			in[id] = true
			for _, pid := range memberOf[id] {
				products[pid] = true
			}
			if len(memberOf[id]) == 0 {
				free = append(free, id)
				if customerFacing(byID[id]) {
					facing = true
				}
			}
		}
		if len(free) == 0 {
			continue // every asset here is already in a product
		}
		var compLinks []Link
		for _, l := range scoped {
			if in[l.A] && in[l.B] {
				compLinks = append(compLinks, l)
			}
		}

		if len(products) > 0 {
			// Linked into a confirmed product: suggest, never add.
			pids := make([]string, 0, len(products))
			for pid := range products {
				pids = append(pids, pid)
			}
			sort.Strings(pids)
			for _, id := range free {
				why := incident(compLinks, id)
				for _, pid := range pids {
					res.Suggestions = append(res.Suggestions, Suggestion{ProductID: pid, AssetID: id, Link: why})
				}
			}
			continue
		}

		freeLinks := append([]Link{}, compLinks...)
		// A product is identified by what a customer reaches. Infrastructure with no customer-facing
		// member — however well linked internally — is left for a human to place, never guessed.
		if !facing {
			res.Unassigned = append(res.Unassigned, Group{AssetIDs: free, Links: freeLinks})
			continue
		}
		res.Proposals = append(res.Proposals, Proposal{Name: proposedName(free, byID), AssetIDs: free, Links: freeLinks})
	}

	sort.Slice(res.Unassigned, func(i, j int) bool { return res.Unassigned[i].AssetIDs[0] < res.Unassigned[j].AssetIDs[0] })
	sort.Slice(res.Proposals, func(i, j int) bool {
		if res.Proposals[i].Name != res.Proposals[j].Name {
			return res.Proposals[i].Name < res.Proposals[j].Name
		}
		return res.Proposals[i].AssetIDs[0] < res.Proposals[j].AssetIDs[0]
	})
	sort.Slice(res.Suggestions, func(i, j int) bool {
		if res.Suggestions[i].ProductID != res.Suggestions[j].ProductID {
			return res.Suggestions[i].ProductID < res.Suggestions[j].ProductID
		}
		return res.Suggestions[i].AssetID < res.Suggestions[j].AssetID
	})
	return res
}

// incident returns the first link touching id — the reason shown beside a suggestion. Links are
// already sorted, so the choice is deterministic.
func incident(links []Link, id string) Link {
	for _, l := range links {
		if l.A == id || l.B == id {
			return l
		}
	}
	return Link{}
}

// proposedName is a starting name the human will usually keep: the registered domain customers
// reach, else the repository, else the cloud account.
func proposedName(members []string, byID map[string]platform.Asset) string {
	for _, id := range members {
		if a := byID[id]; customerFacing(a) {
			if d := RegisteredDomain(a.Target); d != "" {
				return d
			}
			if h := hostOf(a.Target); h != "" {
				return h
			}
		}
	}
	for _, id := range members {
		if a := byID[id]; a.Type == "repository" {
			if k := GitHubRepoNode(a.Target); k != "" {
				return strings.TrimPrefix(k, "code:")
			}
			return a.Target
		}
	}
	for _, id := range members {
		a := byID[id]
		for _, k := range []string{"account_id", "project_id", "subscription_id"} {
			if v := a.Meta[k]; v != "" {
				return a.Target + " " + v
			}
		}
	}
	return byID[members[0]].Target
}

// RegisteredDomain returns the public-suffix eTLD+1 of a target's host, or "" for anything that is
// not a registrable DNS name (an IP, localhost, a bare word).
func RegisteredDomain(target string) string {
	h := hostOf(target)
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return d
}

// hostOf extracts the lower-cased host of a URL or bare domain, without port or trailing dot.
func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		t = u.Hostname()
	} else {
		if i := strings.IndexAny(t, "/?#"); i >= 0 {
			t = t[:i]
		}
		if h, _, err := net.SplitHostPort(t); err == nil {
			t = h
		}
	}
	return strings.TrimSuffix(strings.ToLower(t), ".")
}

// GitHubRepoNode maps a repository asset's URL to the estate graph's node id for it
// ("code:owner/repo"), ONLY for github.com. A GitLab or self-hosted URL with the same path is a
// different repository, and joining it to a GitHub trust would fabricate a deploy relationship.
func GitHubRepoNode(target string) string {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || !strings.EqualFold(u.Hostname(), "github.com") {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	return estategraph.Canonical("code", parts[0]+"/"+repo)
}

// AccountOfPrincipal returns the account a cloud principal node lives in, by exact format:
// an AWS ARN's account field, or a GCP service account's project. "" when it cannot be read.
func AccountOfPrincipal(node string) string {
	switch {
	case strings.HasPrefix(node, "cloud:arn:"):
		f := strings.Split(strings.TrimPrefix(node, "cloud:"), ":")
		if len(f) >= 5 {
			return f[4]
		}
	case strings.HasPrefix(node, "principal:") && strings.HasSuffix(node, ".iam.gserviceaccount.com"):
		email := strings.TrimPrefix(node, "principal:")
		if at := strings.Index(email, "@"); at >= 0 {
			return strings.TrimSuffix(email[at+1:], ".iam.gserviceaccount.com")
		}
	}
	return ""
}

func newLink(a, b string, k LinkKind, why string, ev []string) Link {
	if b < a {
		a, b = b, a
	}
	return Link{A: a, B: b, Kind: k, Why: why, Evidence: ev}
}

func dedupeLinks(in []Link) []Link {
	out := make([]Link, 0, len(in))
	seen := map[string]bool{}
	for _, l := range in {
		k := l.A + "|" + l.B + "|" + string(l.Kind)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	return out
}

func sortedAssets(in []platform.Asset) []platform.Asset {
	out := append([]platform.Asset(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
