package platformapi

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
)

// hostlink.go resolves the hostnames the tenant owns so a cloud inventory can say which instance each
// one runs on (awsinventory.AttachHostnames). Every AWS door calls it — the posted inventory, the
// scheduled live sync and the on-demand sync — so the join cannot depend on which door the account
// came through (the two-doors-disagree shape this tree keeps finding).
//
// Bounded: at most maxHostLookups names, each with its own short timeout, and nothing is looked up
// when the inventory has no instance with a public address to match against.

const (
	maxHostLookups  = 200
	hostLookupLimit = 2 * time.Second
)

// tenantHostnames returns the hostnames of the tenant's web, api and domain assets, deduplicated.
func (d Deps) tenantHostnames(ctx context.Context, tenantID string) []string {
	if d.Store == nil {
		return nil
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range assets {
		switch a.Type {
		case "web_application", "api", "domain":
		default:
			continue
		}
		h := hostOf(a.Target)
		if h == "" || seen[h] || net.ParseIP(h) != nil {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// linkTenantHostnames resolves the tenant's hostnames and joins each to the instance, load balancer or
// CloudFront distribution that serves it (awsinventory.AttachHostnamesTo — see it for what counts as
// evidence). Returns the join and a note describing what could and could not be tied (empty when there
// was nothing to try). Load balancers' own DNS names are resolved too, from the same lookup budget,
// because a hostname is tied to a load balancer by a shared address.
func (d Deps) linkTenantHostnames(ctx context.Context, tenantID string, raw *awsinventory.RawAWS) (awsinventory.HostnameJoin, string) {
	hasTarget := len(raw.LoadBalancers) > 0 || len(raw.Distributions) > 0
	for _, in := range raw.Instances {
		if in.PublicIPAddress != "" {
			hasTarget = true
			break
		}
	}
	hosts := d.tenantHostnames(ctx, tenantID)
	if !hasTarget || len(hosts) == 0 {
		return awsinventory.HostnameJoin{}, ""
	}
	var lbNames []string
	for _, lb := range raw.LoadBalancers {
		if n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(lb.DNSName), ".")); n != "" {
			lbNames = append(lbNames, n)
		}
	}
	skipped := 0
	budget := maxHostLookups - len(lbNames)
	if budget < 0 {
		budget = 0
	}
	if len(hosts) > budget {
		skipped = len(hosts) - budget
		hosts = hosts[:budget]
	}
	lookup := d.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	resolved := map[string][]string{}
	resolveHost := func(h string) {
		lctx, cancel := context.WithTimeout(ctx, hostLookupLimit)
		ips, err := lookup(lctx, h)
		cancel()
		if err == nil && len(ips) > 0 {
			resolved[h] = ips
		}
	}
	for i, n := range lbNames {
		if i >= maxHostLookups {
			break
		}
		resolveHost(n)
	}
	unresolved := 0
	for _, h := range hosts {
		resolveHost(h)
		if _, ok := resolved[h]; !ok {
			unresolved++
		}
	}
	join := awsinventory.AttachHostnamesTo(raw, hosts, resolved)
	note := fmt.Sprintf("%d of your %d web hostname(s) are served by an instance, load balancer or CloudFront "+
		"distribution in this account and are joined to it.", len(join.Linked), len(hosts))
	if n := len(join.Unlinked); n > 0 {
		note += fmt.Sprintf(" %d resolve somewhere this inventory does not cover — another provider, another "+
			"account, or a front door that was not read — so their web findings are not joined to a cloud resource.", n)
	}
	if unresolved > 0 {
		note += fmt.Sprintf(" %d did not resolve.", unresolved)
	}
	if skipped > 0 {
		note += fmt.Sprintf(" %d more were not looked up (limit %d).", skipped, maxHostLookups)
	}
	return join, note
}

// hostnameReport is what the ingest response says about the join. Deliberately NOT a coverage note:
// coverage means "not evaluated — read empty as unread" and feeds the degradation banner, while a
// hostname behind a CDN or load balancer is correct architecture the customer cannot "fix" — a banner
// that fires forever for it is one nobody reads.
func hostnameReport(join awsinventory.HostnameJoin, note string) map[string]any {
	if note == "" {
		return nil
	}
	return map[string]any{"linked": join.Linked, "unlinked": join.Unlinked, "note": note}
}
