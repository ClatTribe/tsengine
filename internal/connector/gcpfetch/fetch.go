// Package gcpfetch reads a connected Google Cloud project LIVE and returns the same
// gcpinventory.RawGCP a customer could otherwise only POST. Before it, GCP was the one cloud whose
// attack paths depended entirely on somebody else's export: the evaluators (gcpiam, gcpwif, the Rhino
// privesc catalogue at 23/23) were built and tested, and a connected project fed them nothing.
//
// It reads, through the read-only access the customer granted tsengine's service account:
//   - the project IAM policy (v3, conditions included) — the bindings everything else is judged by
//   - every service account and its own IAM policy (who may impersonate it, and with which role)
//   - the definition of every non-basic role in use, predefined or custom — gcpiam treats a role it
//     has no definition for as POSSIBLY granting anything, so an unread definition is named, never
//     silently treated as harmless (and never as granting everything either: the firm-allow rule)
//   - Compute instances and VPC firewall rules, joined into each instance's effective ingress
//   - Cloud Storage buckets and whether their IAM policy grants allUsers/allAuthenticatedUsers
//   - Workload Identity Federation pool providers (internal/gcpwif's input)
//
// THE HONESTY RULES (the awsfetch shape):
//   - The project IAM policy is the floor: if it cannot be read, the fetch is an ERROR. A project read
//     with no bindings would render as "nobody can do anything here", the most dangerous all-clear.
//   - Every other surface that cannot be read is NAMED in Skipped with the reason, and nothing from it is
//     invented. A list cut short by a page error is named too: a partial list read as a complete one is
//     the same silent gap one level down.
//   - Bounded: role definitions are capped (MaxRoles) and the cap is reported when hit.
//   - Sensitivity is DECLARED (a bucket label), never inferred from a name.
//
// It makes plain HTTPS calls with an authorised client (the caller supplies one carrying tsengine's
// credentials) rather than pulling in a client library per service, so the request shape is visible
// and every call is testable against a fake.
package gcpfetch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
)

// Doer is the authorised HTTP client (it adds the bearer token).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Endpoints lets tests point every API at a fake. Zero values are Google's.
type Endpoints struct {
	CRM, IAM, Compute, Storage string
}

func (e Endpoints) withDefaults() Endpoints {
	if e.CRM == "" {
		e.CRM = "https://cloudresourcemanager.googleapis.com"
	}
	if e.IAM == "" {
		e.IAM = "https://iam.googleapis.com"
	}
	if e.Compute == "" {
		e.Compute = "https://compute.googleapis.com"
	}
	if e.Storage == "" {
		e.Storage = "https://storage.googleapis.com"
	}
	return e
}

// Fetcher reads one project.
type Fetcher struct {
	Project  string
	Client   Doer
	API      Endpoints
	MaxRoles int // role definitions to resolve (default 200)
	MaxPages int // pages per list call (default 50)
	// SensitiveLabel is the bucket label key whose value "true" DECLARES a bucket sensitive
	// (default "data-sensitivity"; any non-empty value other than "public"/"none" counts).
	SensitiveLabel string
}

// Result is the fetched project plus what was not read.
type Result struct {
	Raw     gcpinventory.RawGCP
	Sources []string
	Skipped map[string]string
}

// Covers reports whether a surface was read.
func (r Result) Covers(surface string) bool {
	for _, s := range r.Sources {
		if s == surface {
			return true
		}
	}
	return false
}

// impersonationRoles let a member act AS a service account.
var impersonationRoles = map[string]bool{
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountUser":         true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.serviceAccountKeyAdmin":     true,
}

// adminRoles mark a principal privileged. Deliberately the basic write roles only: a narrower
// predefined role's reach is decided by its definition through gcpiam, not by a name list here.
var adminRoles = map[string]bool{"roles/owner": true, "roles/editor": true}

// Fetch reads the project.
func (f *Fetcher) Fetch(ctx context.Context) (Result, error) {
	if strings.TrimSpace(f.Project) == "" {
		return Result{}, fmt.Errorf("gcpfetch: no project")
	}
	if f.Client == nil {
		return Result{}, fmt.Errorf("gcpfetch: no authorised client")
	}
	api := f.API.withDefaults()
	res := Result{Raw: gcpinventory.RawGCP{ProjectID: f.Project}, Skipped: map[string]string{}}
	p := url.PathEscape(f.Project)

	// 1. Project IAM policy — the floor.
	var pol iamPolicy
	if err := f.post(ctx, api.CRM+"/v1/projects/"+p+":getIamPolicy", map[string]any{"options": map[string]int{"requestedPolicyVersion": 3}}, &pol); err != nil {
		return res, fmt.Errorf("gcpfetch: the project IAM policy could not be read, so nothing about who can do what is known: %w", err)
	}
	res.Raw.Bindings = pol.bindings()
	res.Sources = append(res.Sources, "iam-policy")
	projectImpersonators := membersWith(res.Raw.Bindings, impersonationRoles)
	admins := map[string]bool{}
	for _, b := range res.Raw.Bindings {
		for _, m := range b.Members {
			if adminRoles[b.Role] && b.Condition == "" {
				admins[m] = true
			}
		}
	}
	seenMember := map[string]bool{}
	for _, b := range res.Raw.Bindings {
		for _, m := range b.Members {
			if strings.HasPrefix(m, "serviceAccount:") || seenMember[m] {
				continue
			}
			seenMember[m] = true
			res.Raw.Members = append(res.Raw.Members, gcpinventory.RawGCPMember{Member: m, Admin: admins[m]})
		}
	}
	sort.Slice(res.Raw.Members, func(i, j int) bool { return res.Raw.Members[i].Member < res.Raw.Members[j].Member })

	// 2. Service accounts and their own policies.
	var sas []struct {
		Email    string `json:"email"`
		Disabled bool   `json:"disabled"`
	}
	if err := f.list(ctx, api.IAM+"/v1/projects/"+p+"/serviceAccounts", "accounts", &sas); err != nil {
		res.Skipped["service-accounts"] = err.Error()
	} else {
		res.Sources = append(res.Sources, "service-accounts")
		var failed []string
		for _, sa := range sas {
			if sa.Disabled {
				continue // a disabled account cannot be impersonated or mint tokens
			}
			entry := gcpinventory.RawGCPSA{Email: sa.Email, Admin: admins["serviceAccount:"+sa.Email]}
			var sp iamPolicy
			if err := f.post(ctx, api.IAM+"/v1/projects/"+p+"/serviceAccounts/"+url.PathEscape(sa.Email)+":getIamPolicy", map[string]any{}, &sp); err != nil {
				failed = append(failed, sa.Email)
			} else {
				entry.Bindings = sp.bindings()
			}
			imps := map[string]bool{}
			for _, m := range projectImpersonators {
				imps[m] = true
			}
			for _, m := range membersWith(entry.Bindings, impersonationRoles) {
				imps[m] = true
			}
			for m := range imps {
				entry.Impersonators = append(entry.Impersonators, m)
			}
			sort.Strings(entry.Impersonators)
			res.Raw.ServiceAccounts = append(res.Raw.ServiceAccounts, entry)
		}
		if len(failed) > 0 {
			res.Skipped["service-account-policies"] = fmt.Sprintf("the IAM policy of %d service account(s) could not be read, so who may impersonate them is unknown: %s",
				len(failed), strings.Join(capList(failed, 10), ", "))
		}
	}

	// 3. Role definitions for every non-basic role in use.
	f.resolveRoles(ctx, api, &res)

	// 4. Instances + firewalls.
	f.readCompute(ctx, api, p, &res)

	// 5. Buckets.
	f.readBuckets(ctx, api, p, &res)

	// 6. Workload Identity Federation.
	f.readWIF(ctx, api, p, &res)

	return res, nil
}

type iamPolicy struct {
	Bindings []struct {
		Role      string   `json:"role"`
		Members   []string `json:"members"`
		Condition *struct {
			Expression string `json:"expression"`
		} `json:"condition"`
	} `json:"bindings"`
}

func (p iamPolicy) bindings() []gcpinventory.RawGCPBinding {
	var out []gcpinventory.RawGCPBinding
	for _, b := range p.Bindings {
		rb := gcpinventory.RawGCPBinding{Role: b.Role, Members: append([]string(nil), b.Members...)}
		if b.Condition != nil {
			rb.Condition = b.Condition.Expression
		}
		out = append(out, rb)
	}
	return out
}

func membersWith(bs []gcpinventory.RawGCPBinding, roles map[string]bool) []string {
	var out []string
	for _, b := range bs {
		if roles[b.Role] && b.Condition == "" {
			out = append(out, b.Members...)
		}
	}
	return out
}

func (f *Fetcher) resolveRoles(ctx context.Context, api Endpoints, res *Result) {
	max := f.MaxRoles
	if max <= 0 {
		max = 200
	}
	want := map[string]bool{}
	add := func(bs []gcpinventory.RawGCPBinding) {
		for _, b := range bs {
			switch b.Role {
			case "roles/owner", "roles/editor", "roles/viewer":
				continue // understood inline by gcpiam
			}
			want[b.Role] = true
		}
	}
	add(res.Raw.Bindings)
	for _, sa := range res.Raw.ServiceAccounts {
		add(sa.Bindings)
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	res.Raw.RoleDefs = map[string][]string{}
	var unread []string
	for i, name := range names {
		if i >= max {
			res.Skipped["role-definitions-cap"] = fmt.Sprintf("%d roles are in use and only the first %d definitions were read; the rest are treated as unknown, never as harmless", len(names), max)
			break
		}
		// Predefined roles live at /v1/roles/X, custom ones at /v1/projects/P/roles/X or
		// /v1/organizations/O/roles/X — the role name IS the resource path.
		var def struct {
			IncludedPermissions []string `json:"includedPermissions"`
		}
		if err := f.get(ctx, api.IAM+"/v1/"+name, &def); err != nil {
			unread = append(unread, name)
			continue
		}
		res.Raw.RoleDefs[name] = def.IncludedPermissions
	}
	if len(names) > 0 {
		res.Sources = append(res.Sources, "role-definitions")
	}
	if len(unread) > 0 {
		res.Skipped["role-definitions"] = fmt.Sprintf("%d role definition(s) could not be read and are treated as unknown: %s",
			len(unread), strings.Join(capList(unread, 10), ", "))
	}
}

func (f *Fetcher) readCompute(ctx context.Context, api Endpoints, p string, res *Result) {
	type fwRule struct {
		Name         string   `json:"name"`
		Network      string   `json:"network"`
		Direction    string   `json:"direction"`
		Disabled     bool     `json:"disabled"`
		SourceRanges []string `json:"sourceRanges"`
		TargetTags   []string `json:"targetTags"`
		TargetSAs    []string `json:"targetServiceAccounts"`
		Allowed      []struct {
			Proto string   `json:"IPProtocol"`
			Ports []string `json:"ports"`
		} `json:"allowed"`
	}
	var rules []fwRule
	fwErr := f.list(ctx, api.Compute+"/compute/v1/projects/"+p+"/global/firewalls", "items", &rules)

	var agg struct {
		Items map[string]struct {
			Instances []struct {
				Name              string                   `json:"name"`
				Zone              string                   `json:"zone"`
				Tags              struct{ Items []string } `json:"tags"`
				NetworkInterfaces []struct {
					Network       string `json:"network"`
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
				ServiceAccounts []struct {
					Email string `json:"email"`
				} `json:"serviceAccounts"`
			} `json:"instances"`
		} `json:"items"`
	}
	if err := f.get(ctx, api.Compute+"/compute/v1/projects/"+p+"/aggregated/instances", &agg); err != nil {
		res.Skipped["compute"] = err.Error()
		return
	}
	res.Sources = append(res.Sources, "compute")
	if fwErr != nil {
		// Instances without their firewall rules would carry no ingress and so no reach edge — which
		// reads as "not reachable". Say we could not tell instead.
		res.Skipped["firewalls"] = "firewall rules could not be read, so no instance's internet reachability was evaluated: " + fwErr.Error()
	}
	zones := make([]string, 0, len(agg.Items))
	for z := range agg.Items {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	for _, z := range zones {
		for _, in := range agg.Items[z].Instances {
			ri := gcpinventory.RawGCPInstance{Name: in.Name, Region: lastSeg(in.Zone)}
			networks := map[string]bool{}
			for _, ni := range in.NetworkInterfaces {
				networks[ni.Network] = true
				for _, ac := range ni.AccessConfigs {
					if ac.NatIP != "" {
						ri.ExternalIP = true
					}
				}
			}
			saEmails := map[string]bool{}
			for _, sa := range in.ServiceAccounts {
				saEmails[sa.Email] = true
			}
			tags := map[string]bool{}
			for _, t := range in.Tags.Items {
				tags[t] = true
			}
			if fwErr == nil {
				var eff []cloudgraph.SGRule
				for _, r := range rules {
					if r.Disabled || !strings.EqualFold(r.Direction, "INGRESS") || !networks[r.Network] || !targets(r.TargetTags, r.TargetSAs, tags, saEmails) {
						continue
					}
					for _, a := range r.Allowed {
						proto := strings.ToLower(a.Proto)
						if proto == "all" {
							proto = "-1"
						}
						spans := portSpans(a.Ports)
						for _, src := range r.SourceRanges {
							for _, sp := range spans {
								eff = append(eff, cloudgraph.SGRule{Proto: proto, CIDR: src, PortFrom: sp[0], PortTo: sp[1]})
							}
						}
					}
				}
				if b, err := json.Marshal(eff); err == nil && len(eff) > 0 {
					ri.IngressJSON = string(b)
				}
				ri.ServicePort, ri.ServiceProto = worldOpenPort(eff)
			}
			res.Raw.Instances = append(res.Raw.Instances, ri)
		}
	}
}

// targets reports whether a firewall rule applies to an instance: no target means every instance on
// the network; otherwise a shared tag or a target service account.
func targets(ruleTags, ruleSAs []string, tags, sas map[string]bool) bool {
	if len(ruleTags) == 0 && len(ruleSAs) == 0 {
		return true
	}
	for _, t := range ruleTags {
		if tags[t] {
			return true
		}
	}
	for _, s := range ruleSAs {
		if sas[s] {
			return true
		}
	}
	return false
}

// portSpans turns ["22", "8000-8100"] into spans; no ports means every port.
func portSpans(ports []string) [][2]int {
	if len(ports) == 0 {
		return [][2]int{{0, 65535}}
	}
	var out [][2]int
	for _, p := range ports {
		lo, hi, ok := strings.Cut(p, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		if err1 != nil {
			continue
		}
		b := a
		if ok {
			if v, err := strconv.Atoi(strings.TrimSpace(hi)); err == nil {
				b = v
			}
		}
		out = append(out, [2]int{a, b})
	}
	return out
}

// worldOpenPort picks the lowest port a rule opens to the whole internet, so the graph can draw the
// reach edge on a port that really is open. A rule opening every port is represented by 22 (it is open
// too). Nothing world-open → 0, and the graph correctly draws no edge.
func worldOpenPort(rules []cloudgraph.SGRule) (int, string) {
	best, proto := 0, ""
	for _, r := range rules {
		if r.CIDR != "0.0.0.0/0" && r.CIDR != "::/0" {
			continue
		}
		port := r.PortFrom
		if r.PortFrom == 0 && r.PortTo == 65535 {
			port = 22
		}
		if port == 0 {
			continue
		}
		if best == 0 || port < best {
			best, proto = port, r.Proto
		}
	}
	if proto == "-1" || proto == "" {
		proto = "tcp"
	}
	return best, proto
}

func (f *Fetcher) readBuckets(ctx context.Context, api Endpoints, p string, res *Result) {
	var buckets []struct {
		Name     string            `json:"name"`
		Location string            `json:"location"`
		Labels   map[string]string `json:"labels"`
	}
	if err := f.list(ctx, api.Storage+"/storage/v1/b?project="+p, "items", &buckets); err != nil {
		res.Skipped["storage"] = err.Error()
		return
	}
	res.Sources = append(res.Sources, "storage")
	label := f.SensitiveLabel
	if label == "" {
		label = "data-sensitivity"
	}
	var unread []string
	for _, b := range buckets {
		rb := gcpinventory.RawGCPBucket{Name: b.Name, Region: strings.ToLower(b.Location)}
		if v := strings.ToLower(strings.TrimSpace(b.Labels[label])); v != "" && v != "public" && v != "none" && v != "false" {
			rb.Sensitive = true
		}
		var pol iamPolicy
		if err := f.get(ctx, api.Storage+"/storage/v1/b/"+url.PathEscape(b.Name)+"/iam", &pol); err != nil {
			unread = append(unread, b.Name)
		} else {
			for _, bd := range pol.Bindings {
				for _, m := range bd.Members {
					if m == "allUsers" || m == "allAuthenticatedUsers" {
						rb.Public = true
					}
				}
			}
		}
		res.Raw.Buckets = append(res.Raw.Buckets, rb)
	}
	if len(unread) > 0 {
		res.Skipped["bucket-policies"] = fmt.Sprintf("%d bucket polic(ies) could not be read, so whether they are public is unknown: %s",
			len(unread), strings.Join(capList(unread, 10), ", "))
	}
}

func (f *Fetcher) readWIF(ctx context.Context, api Endpoints, p string, res *Result) {
	var proj struct {
		ProjectNumber string `json:"projectNumber"`
	}
	if err := f.get(ctx, api.CRM+"/v1/projects/"+p, &proj); err != nil || proj.ProjectNumber == "" {
		res.Skipped["workload-identity"] = "the project number could not be read, so workload identity federation was not examined"
		return
	}
	var pools []struct {
		Name     string `json:"name"`
		Disabled bool   `json:"disabled"`
	}
	if err := f.list(ctx, api.IAM+"/v1/projects/"+p+"/locations/global/workloadIdentityPools", "workloadIdentityPools", &pools); err != nil {
		res.Skipped["workload-identity"] = err.Error()
		return
	}
	res.Sources = append(res.Sources, "workload-identity")
	var failed []string
	for _, pool := range pools {
		if pool.Disabled {
			continue
		}
		var providers []struct {
			Name               string            `json:"name"`
			Disabled           bool              `json:"disabled"`
			AttributeMapping   map[string]string `json:"attributeMapping"`
			AttributeCondition string            `json:"attributeCondition"`
			OIDC               *struct {
				IssuerURI        string   `json:"issuerUri"`
				AllowedAudiences []string `json:"allowedAudiences"`
			} `json:"oidc"`
		}
		if err := f.list(ctx, api.IAM+"/v1/"+pool.Name+"/providers", "workloadIdentityPoolProviders", &providers); err != nil {
			failed = append(failed, lastSeg(pool.Name))
			continue
		}
		for _, pr := range providers {
			if pr.Disabled {
				continue
			}
			rp := gcpinventory.RawGCPWIFProvider{ProjectNumber: proj.ProjectNumber, PoolID: lastSeg(pool.Name), ID: lastSeg(pr.Name),
				AttributeMapping: pr.AttributeMapping, AttributeCondition: pr.AttributeCondition}
			if pr.OIDC != nil {
				rp.IssuerURI, rp.AllowedAudiences = pr.OIDC.IssuerURI, pr.OIDC.AllowedAudiences
			}
			res.Raw.WIFProviders = append(res.Raw.WIFProviders, rp)
		}
	}
	if len(failed) > 0 {
		res.Skipped["workload-identity-providers"] = "the providers of these pools could not be read: " + strings.Join(capList(failed, 10), ", ")
	}
}

// --- HTTP ---

func (f *Fetcher) get(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return f.do(req, into)
}

func (f *Fetcher) post(ctx context.Context, u string, body any, into any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return f.do(req, into)
}

func (f *Fetcher) do(req *http.Request, into any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("%s: HTTP %d: %s", req.URL.Path, resp.StatusCode, msg)
	}
	// A 2xx that is not JSON (a proxy's HTML page) is an error, never an empty result.
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s: the response was not the JSON the API returns: %w", req.URL.Path, err)
	}
	return nil
}

// list follows nextPageToken, appending each page's `field` array into into (a pointer to a slice).
// A page failing part-way is an ERROR: a list cut short read as complete is a silent gap.
func (f *Fetcher) list(ctx context.Context, base, field string, into any) error {
	max := f.MaxPages
	if max <= 0 {
		max = 50
	}
	var all []json.RawMessage
	token := ""
	for page := 0; ; page++ {
		if page >= max {
			return fmt.Errorf("%s: more than %d pages; the list was not read to the end", base, max)
		}
		u := base
		if token != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			u += sep + "pageToken=" + url.QueryEscape(token)
		}
		var raw map[string]json.RawMessage
		if err := f.get(ctx, u, &raw); err != nil {
			return err
		}
		var items []json.RawMessage
		if v, ok := raw[field]; ok {
			if err := json.Unmarshal(v, &items); err != nil {
				return fmt.Errorf("%s: %w", base, err)
			}
		}
		all = append(all, items...)
		token = ""
		if v, ok := raw["nextPageToken"]; ok {
			_ = json.Unmarshal(v, &token)
		}
		if token == "" {
			break
		}
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

func lastSeg(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func capList(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(xs[:n:n], fmt.Sprintf("and %d more", len(xs)-n))
}
