package ip

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// Per-port nuclei tag routing — the ip_address analog of the web
// "don't run list-mode tools per-URL" rule. Without it, nuclei runs its
// whole ~10k-template corpus against every open port; with it, each port
// sees only the ~20-100 templates relevant to its likely service. strix
// measured ~50x speedup + better signal-to-noise from exactly this
// (iter-Q5.43). The map is the routing table; an unlisted port falls back
// to the generic "network" tag set.
var portToNucleiTags = map[int]string{
	21:    "ftp",
	22:    "ssh,openssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http,tech",
	110:   "pop3",
	111:   "rpc",
	135:   "msrpc",
	139:   "smb",
	143:   "imap",
	443:   "ssl,tls,http",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http,tech",
	8443:  "ssl,tls,http",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// nucleiTagsForPort returns the routed tag set for a port, or "network"
// (the catch-all for protocol-level templates) when the port is unknown.
func nucleiTagsForPort(port int) string {
	if tags, ok := portToNucleiTags[port]; ok {
		return tags
	}
	return "network"
}

// httpLikePort reports whether a port is worth an httpx probe. We probe
// the well-known HTTP/TLS ports plus the common alternates; httpx itself
// confirms whether a real HTTP service answers.
var httpLikePorts = map[int]bool{
	80: true, 443: true, 8000: true, 8008: true, 8080: true,
	8081: true, 8443: true, 8888: true, 3000: true, 5000: true,
}

// portToHydraService maps an open port to the hydra module that
// default-cred checks it. Only auth-bearing services — the escalation
// engine fires hydra on these and nothing else (intrusive → targeted).
var portToHydraService = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 445: "smb",
	1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
	5900: "vnc", 6379: "redis",
}

// hydraServiceForPort returns the hydra service for an auth-bearing port.
func hydraServiceForPort(port int) (string, bool) {
	s, ok := portToHydraService[port]
	return s, ok
}

// splitHostPort extracts the port from a "host:port" surface entry.
// Returns ok=false for a bare host (no port) so PlanFanout can treat it
// as the recon-empty fallback. Handles IPv6 brackets via net.SplitHostPort
// with a bare-host fallback.
func splitHostPort(entry string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(entry)
	if err != nil {
		return entry, 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return h, 0, false
	}
	return h, n, true
}

// discoveredPorts returns the sorted, deduped port list across a surface
// (for nmap's -p value). Empty when nothing but the bare target was found.
func discoveredPorts(surface []string) []int {
	seen := map[int]struct{}{}
	var ports []int
	for _, e := range surface {
		if _, p, ok := splitHostPort(e); ok {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	sort.Ints(ports)
	return ports
}

func joinPorts(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ",")
}

// hostPort reassembles a host:port endpoint (IPv6-safe via net.JoinHostPort).
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// joinLines newline-joins endpoints for a tool's "targets" list arg.
func joinLines(ss []string) string { return strings.Join(ss, "\n") }
