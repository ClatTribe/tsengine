// Package correlate is the cross-asset attack-path layer (roadmap §3/§4, the
// Prioritization pillar). A single asset's scan answers "is this finding real?".
// Correlation answers the harder question across asset boundaries: does a finding
// over HERE chain to a crown jewel over THERE? — e.g. a web SQLi that leaks an AWS
// key → the cloud IAM user that key belongs to → privilege escalation to admin.
//
// Grounding holds across the boundary too: a chain hop is emitted only when a
// concrete shared identifier (an AWS key, an ARN, a host) appears in BOTH findings.
// The engine never asserts a link it can't point at.
package correlate

import (
	"regexp"
	"sort"
	"strings"
)

// EntityKind is the type of a correlatable identifier.
type EntityKind string

const (
	EntAWSKey EntityKind = "aws_key"
	EntARN    EntityKind = "arn"
	EntHost   EntityKind = "host"
	EntIP     EntityKind = "ip"
	EntBucket EntityKind = "s3_bucket"
	// EntEmail bridges the IDENTITY surface (operate: Okta/GW/M365 — endpoint is the user's email) to
	// code/cloud findings that name the same human/principal. The canonical breach path: a no-MFA admin
	// (identity) who also has cloud admin (cloud) and prod repo push (code) is ONE blast radius, not three
	// shrugs. Grounded: a real shared email; generic mailbox/vendor local-parts are excluded (genericEmailLocal).
	EntEmail EntityKind = "email"
)

// Entity is a shared identifier that can bridge two assets.
type Entity struct {
	Kind  EntityKind `json:"kind"`
	Value string     `json:"value"`
}

func (e Entity) key() string { return string(e.Kind) + "|" + strings.ToLower(e.Value) }

// Finding is the correlation-normalized view of one issue.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Tool        string   `json:"tool,omitempty"`
	Description string   `json:"description,omitempty"`
	Verified    bool     `json:"verified,omitempty"`
	Entities    []Entity `json:"entities,omitempty"` // explicit; correlator also extracts
}

// Asset is one scanned target + its findings.
type Asset struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"` // web_application | api | ip_address | domain | repository | container_image | cloud_account
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

// Step is one hop in a chain.
type Step struct {
	AssetType   string `json:"asset_type"`
	AssetTarget string `json:"asset_target"`
	FindingID   string `json:"finding_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Verified    bool   `json:"verified,omitempty"`
	ViaEntity   string `json:"via_entity,omitempty"` // the shared identifier that led to the NEXT step
	CrownJewel  bool   `json:"crown_jewel,omitempty"`
}

// Chain is a grounded cross-asset attack path: an external entry → … → crown jewel.
type Chain struct {
	Severity string `json:"severity"`
	Steps    []Step `json:"steps"`
}

// flat node: a finding within an asset, plus its extracted entities + roles.
type node struct {
	ai, fi   int
	asset    *Asset
	finding  *Finding
	entities []Entity
	entry    bool
	crown    bool
}

// Correlate builds the cross-asset graph and returns grounded chains from external
// entry points to crown jewels, deduplicated and severity-sorted.
func Correlate(assets []Asset) []Chain {
	var nodes []*node
	for ai := range assets {
		a := &assets[ai]
		for fi := range a.Findings {
			f := &a.Findings[fi]
			ents := dedupeEntities(append(extractEntities(*f), addTargetEntity(a)...))
			nodes = append(nodes, &node{
				ai: ai, fi: fi, asset: a, finding: f, entities: ents,
				entry: isEntry(a, *f), crown: isCrownJewel(a, *f),
			})
		}
	}

	// entity → nodes index
	byEntity := map[string][]int{}
	for i, n := range nodes {
		for _, e := range n.entities {
			byEntity[e.key()] = append(byEntity[e.key()], i)
		}
	}

	// adjacency: an edge between two nodes in DIFFERENT assets that share an entity.
	type edge struct {
		to  int
		via Entity
	}
	adj := make([][]edge, len(nodes))
	for i, n := range nodes {
		seen := map[int]bool{}
		for _, e := range n.entities {
			for _, j := range byEntity[e.key()] {
				if j == i || nodes[j].ai == n.ai || seen[j] {
					continue
				}
				seen[j] = true
				adj[i] = append(adj[i], edge{to: j, via: e})
			}
		}
		sort.Slice(adj[i], func(a, b int) bool { return adj[i][a].to < adj[i][b].to })
	}

	// BFS from each entry node to the nearest crown-jewel node.
	var chains []Chain
	emitted := map[string]bool{}
	for s := range nodes {
		if !nodes[s].entry {
			continue
		}
		parent := map[int]int{s: -1}
		via := map[int]Entity{}
		queue := []int{s}
		target := -1
		for len(queue) > 0 && target < 0 {
			cur := queue[0]
			queue = queue[1:]
			if nodes[cur].crown && cur != s {
				target = cur
				break
			}
			for _, e := range adj[cur] {
				if _, ok := parent[e.to]; !ok {
					parent[e.to] = cur
					via[e.to] = e.via
					queue = append(queue, e.to)
				}
			}
		}
		if target < 0 {
			continue
		}
		// reconstruct
		var path []int
		for n := target; n >= 0; n = parent[n] {
			path = append(path, n)
		}
		for l, r := 0, len(path)-1; l < r; l, r = l+1, r-1 {
			path[l], path[r] = path[r], path[l]
		}
		ch := buildChain(nodes, path, via)
		k := chainKey(ch)
		if !emitted[k] {
			emitted[k] = true
			chains = append(chains, ch)
		}
	}

	sort.SliceStable(chains, func(a, b int) bool {
		return sevRank(chains[a].Severity) < sevRank(chains[b].Severity)
	})
	return chains
}

func buildChain(nodes []*node, path []int, via map[int]Entity) Chain {
	ch := Chain{}
	worst := 5
	for idx, ni := range path {
		n := nodes[ni]
		st := Step{
			AssetType: n.asset.Type, AssetTarget: n.asset.Target,
			FindingID: n.finding.ID, Title: n.finding.Title, Severity: n.finding.Severity,
			Verified: n.finding.Verified, CrownJewel: n.crown,
		}
		if idx < len(path)-1 {
			e := via[path[idx+1]]
			st.ViaEntity = string(e.Kind) + " " + e.Value
		}
		ch.Steps = append(ch.Steps, st)
		if r := sevRank(n.finding.Severity); r < worst {
			worst = r
		}
	}
	// the chain is as severe as its worst link (and it reaches a crown jewel).
	ch.Severity = sevName(worst)
	return ch
}

// --- entity extraction ---

var (
	awsKeyRe = regexp.MustCompile(`A[KS]IA[0-9A-Z]{16}`)
	arnRe    = regexp.MustCompile(`arn:aws:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[\w./:*-]+`)
	bucketRe = regexp.MustCompile(`(?:s3://|arn:aws:s3:::)([a-z0-9.-]{3,63})`)
	ipRe     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailRe  = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
)

// genericEmailLocal: local-parts that are almost never the SUBJECT of a finding (mailboxes, reporters,
// vendor/role addresses). Extracting them as identity entities would bridge two unrelated findings that
// merely cite the same support inbox — so we exclude them. The email bridge is for a real human/principal.
var genericEmailLocal = map[string]bool{
	"noreply": true, "no-reply": true, "donotreply": true, "do-not-reply": true, "notifications": true,
	"security": true, "abuse": true, "admin": true, "administrator": true, "support": true, "help": true,
	"info": true, "hello": true, "contact": true, "sales": true, "team": true, "billing": true,
	"root": true, "postmaster": true, "mailer-daemon": true, "example": true, "test": true,
}

func extractEntities(f Finding) []Entity {
	blob := f.Title + " " + f.Description + " " + f.Endpoint
	var out []Entity
	out = append(out, f.Entities...)
	for _, k := range awsKeyRe.FindAllString(blob, -1) {
		out = append(out, Entity{EntAWSKey, k})
	}
	for _, a := range arnRe.FindAllString(blob, -1) {
		out = append(out, Entity{EntARN, a})
	}
	for _, m := range bucketRe.FindAllStringSubmatch(blob, -1) {
		out = append(out, Entity{EntBucket, m[1]})
	}
	if h := hostOf(f.Endpoint); h != "" {
		out = append(out, Entity{EntHost, h})
	}
	for _, ip := range ipRe.FindAllString(f.Endpoint, -1) {
		out = append(out, Entity{EntIP, ip})
	}
	// Identity bridge: a real human/principal email shared across surfaces (operate→cloud→code). Skip
	// generic mailbox/vendor local-parts so a shared support address never invents a chain (§10).
	for _, m := range emailRe.FindAllString(blob, -1) {
		local := strings.ToLower(m)
		if i := strings.IndexByte(local, '@'); i > 0 && genericEmailLocal[local[:i]] {
			continue
		}
		out = append(out, Entity{EntEmail, m})
	}
	return out
}

// addTargetEntity makes a network asset's own target a bridgeable entity so a
// finding on host H links to the ip/domain asset for H.
func addTargetEntity(a *Asset) []Entity {
	switch a.Type {
	case "web_application", "api", "ip_address", "domain":
		if h := hostOf(a.Target); h != "" {
			return []Entity{{EntHost, h}}
		}
		if ipRe.MatchString(a.Target) {
			return []Entity{{EntIP, ipRe.FindString(a.Target)}}
		}
	}
	return nil
}

func dedupeEntities(in []Entity) []Entity {
	seen := map[string]bool{}
	var out []Entity
	for _, e := range in {
		if e.Value == "" || seen[e.key()] {
			continue
		}
		seen[e.key()] = true
		out = append(out, e)
	}
	return out
}

// --- role inference ---

func isEntry(a *Asset, f Finding) bool {
	switch a.Type {
	case "web_application", "api", "ip_address", "domain":
		return f.Verified || sevRank(f.Severity) <= sevRank("high")
	case "workspace", "saas":
		// A compromised IDENTITY is a real entry point: a no-MFA admin, a leaked credential, or an
		// over-privileged OAuth app is how an attacker gets IN (phish / credential theft / app compromise),
		// then pivots via the shared principal (email/app) to cloud or code. High+ only, same bar as the rest.
		return f.Verified || sevRank(f.Severity) <= sevRank("high")
	case "repository", "container_image":
		// The CODE→CLOUD wedge (the homepage AttackPathHero): a secret leaked in source / baked into an
		// image layer is a real initial-access vector — an attacker who reads the repo, its git history, or
		// a published image obtains the credential, then pivots via the shared key/ARN/bucket to the cloud
		// crown jewel. FromScan already extracts those secrets from repo/container findings (TestFromScan),
		// but without an entry role the repo node was never a BFS start, so the flagship chain was dropped.
		// Grounded (§10): a repo/container endpoint yields no host/IP entity, so the bridge is secret-only —
		// admitting these as entries adds no coincidental-host risk; a chain still needs a REAL shared secret.
		return f.Verified || sevRank(f.Severity) <= sevRank("high")
	}
	return false
}

var crownRe = regexp.MustCompile(`(?i)(administrator|admin access|privilege escalation|privesc|crown jewel|full access|assume.*admin|\*:\*)`)

func isCrownJewel(a *Asset, f Finding) bool {
	if a.Type != "cloud_account" {
		return false
	}
	return crownRe.MatchString(f.Title + " " + f.Description)
}

// --- helpers ---

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sevRank(s string) int {
	if r, ok := sevOrder[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

func sevName(r int) string {
	for s, x := range sevOrder {
		if x == r {
			return s
		}
	}
	return "info"
}

func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '@'); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		raw = raw[:i]
	}
	if strings.Contains(raw, ".") && !ipRe.MatchString(raw) {
		return strings.ToLower(raw)
	}
	if ipRe.MatchString(raw) {
		return strings.ToLower(raw)
	}
	return ""
}

func chainKey(c Chain) string {
	var b strings.Builder
	for _, s := range c.Steps {
		b.WriteString(s.AssetType + ":" + s.FindingID + ">")
	}
	return b.String()
}
