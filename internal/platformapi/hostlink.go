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

// linkTenantHostnames resolves the tenant's hostnames and attaches each to the instance it resolves to.
// Returns the join and a coverage note describing what could and could not be tied (empty when there
// was nothing to try).
func (d Deps) linkTenantHostnames(ctx context.Context, tenantID string, raw *awsinventory.RawAWS) (awsinventory.HostnameJoin, string) {
	hasAddr := false
	for _, in := range raw.Instances {
		if in.PublicIPAddress != "" {
			hasAddr = true
			break
		}
	}
	hosts := d.tenantHostnames(ctx, tenantID)
	if !hasAddr || len(hosts) == 0 {
		return awsinventory.HostnameJoin{}, ""
	}
	skipped := 0
	if len(hosts) > maxHostLookups {
		skipped = len(hosts) - maxHostLookups
		hosts = hosts[:maxHostLookups]
	}
	lookup := d.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	resolved := map[string][]string{}
	for _, h := range hosts {
		lctx, cancel := context.WithTimeout(ctx, hostLookupLimit)
		ips, err := lookup(lctx, h)
		cancel()
		if err == nil && len(ips) > 0 {
			resolved[h] = ips
		}
	}
	join := awsinventory.AttachHostnames(raw, resolved)
	note := fmt.Sprintf("%d of your %d web hostname(s) resolve to an instance in this account and are joined to it.",
		len(join.Linked), len(hosts))
	if n := len(join.Unlinked); n > 0 {
		note += fmt.Sprintf(" %d resolve somewhere else — a load balancer, a CDN or another provider, none of which "+
			"this inventory reads — so their web findings are not joined to a cloud resource.", n)
	}
	if n := len(hosts) - len(resolved); n > 0 {
		note += fmt.Sprintf(" %d did not resolve.", n)
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
