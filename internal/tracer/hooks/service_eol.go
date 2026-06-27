package hooks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// ServiceEOL flags an nmap-detected network service whose version is outdated / past security support. nmap
// already names the product + version (e.g. "OpenSSH 6.6.1p1", "Apache httpd 2.4.7" — surfaced as info
// "open-port" findings); on a real scan of scanme.nmap.org those ran years-old, CVE-bearing builds yet were
// reported as plain info. This L1.5 hook compares the running version against a curated minimum-safe-version
// table for common internet-facing services and, when the build is older, bumps the finding's severity +
// annotates it with the upgrade guidance — so a daily-driver user learns "your SSH/web server is dangerously
// out of date", not just "port 22 is open".
//
// Grounded (§10/§13): this is reference data + comparison, NOT a new in-house detector. It acts ONLY on a
// real nmap product+version it can match against a curated entry AND parse numerically; anything else (a
// service not in the table, an unparseable version) is left untouched — never a guessed verdict. The table
// is conservative (min-safe = the oldest still-supported release at authoring time) so a flag is defensible.
type ServiceEOL struct{}

// NewServiceEOL constructs the hook.
func NewServiceEOL() *ServiceEOL { return &ServiceEOL{} }

// Name identifies the hook in the L1.5 chain + audit log.
func (*ServiceEOL) Name() string { return "service_eol" }

type minSafe struct {
	ver    string
	reason string
}

// serviceMinSafe: normalized nmap product → oldest version still receiving security support + why it matters.
// Keep entries to widely-exposed services where "outdated" is unambiguously a security finding. Adding a
// service is one line; a service NOT here is simply never flagged (honest, never padded).
var serviceMinSafe = map[string]minSafe{
	"openssh":      {"8.0", "OpenSSH before 8.0 is years out of date (multiple auth/DoS CVEs)"},
	"apache httpd": {"2.4.56", "Apache httpd 2.4.x before 2.4.56 has known RCE/SSRF/info-leak CVEs"},
	"apache":       {"2.4.56", "Apache httpd 2.4.x before 2.4.56 has known RCE/SSRF/info-leak CVEs"},
	"nginx":        {"1.24.0", "nginx before 1.24 has known CVEs (resolver, mp4 module, etc.)"},
	"openssl":      {"1.1.1", "OpenSSL before 1.1.1 is end-of-life and receives no security fixes"},
	"proftpd":      {"1.3.8", "ProFTPD before 1.3.8 has known remote-code-execution CVEs"},
	"vsftpd":       {"3.0.5", "vsftpd before 3.0.5 is dated; upgrade to the current release"},
	"exim smtpd":   {"4.96", "Exim before 4.96 has critical (wormable) RCE CVEs"},
	"exim":         {"4.96", "Exim before 4.96 has critical (wormable) RCE CVEs"},
	"postfix":      {"3.6", "Postfix before 3.6 no longer receives upstream security support"},
	"mysql":        {"8.0", "MySQL before 8.0 (and 5.7 after its Oct-2023 EOL) gets no security fixes"},
	"mariadb":      {"10.6", "MariaDB before 10.6 (an LTS) is past mainstream support"},
	"postgresql":   {"12", "PostgreSQL before major 12 is end-of-life"},
	"isc bind":     {"9.18", "ISC BIND before 9.18 (the current stable) has known DoS CVEs"},
	"bind":         {"9.18", "ISC BIND before 9.18 (the current stable) has known DoS CVEs"},
	// Data stores + app servers that are high-impact when exposed and outdated (unauth access / RCE).
	"redis":         {"7.0", "Redis before 7.0 is past support (6.x EOL); an exposed, outdated Redis is a common unauth-RCE/data-theft path"},
	"apache tomcat": {"9.0", "Apache Tomcat before 9.0 (8.5 reached EOL) carries known RCE/deserialization CVEs (e.g. Ghostcat)"},
	"tomcat":        {"9.0", "Apache Tomcat before 9.0 (8.5 reached EOL) carries known RCE/deserialization CVEs (e.g. Ghostcat)"},
	"mongodb":       {"6.0", "MongoDB before 6.0 is past support (5.0 reached EOL); an exposed, outdated MongoDB risks unauth data access"},
	"elasticsearch": {"7.17", "Elasticsearch before 7.17 (6.x EOL) has known RCE/info-disclosure CVEs and is dangerous when internet-exposed"},
	"memcached":     {"1.6", "memcached before 1.6 is dated; an exposed instance enables UDP amplification + plaintext data theft"},
	"dovecot":       {"2.3", "Dovecot before 2.3 is past mainstream support and has known IMAP/POP3 CVEs"},
	"squid":         {"6.0", "Squid before 6.0 (5.x EOL) has many request-smuggling / overflow CVEs"},
	"php":           {"8.1", "PHP before 8.1 is end-of-life (7.x and 8.0 receive no security fixes)"},
	// More commonly internet-exposed services that are high-impact when outdated.
	"samba":    {"4.18", "Samba before 4.18 is past support and carries the SMB RCE/auth-bypass CVE family (e.g. ZeroLogon-adjacent, CVE-2021-44142)"},
	"smbd":     {"4.18", "Samba (smbd) before 4.18 is past support and carries the SMB RCE/auth-bypass CVE family"},
	"haproxy":  {"2.6", "HAProxy before 2.6 (an LTS) has known request-smuggling CVEs (e.g. CVE-2023-25725)"},
	"lighttpd": {"1.4.76", "lighttpd before 1.4.76 has known DoS / info-disclosure CVEs"},
	"couchdb":  {"3.3", "Apache CouchDB before 3.3 has a remote-code-execution CVE (CVE-2022-24706) and is dangerous when internet-exposed"},
	"rabbitmq": {"3.12", "RabbitMQ before 3.12 is past support and has known auth/DoS CVEs; an exposed broker is a lateral-movement path"},
}

// Apply flags + bumps an outdated service. Annotation-only otherwise.
func (h *ServiceEOL) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	if f.Tool != "nmap" || f.ToolArgs == nil {
		return f, nil, true
	}
	product := strings.ToLower(strings.TrimSpace(f.ToolArgs["product"]))
	version := strings.TrimSpace(f.ToolArgs["version"])
	if product == "" || version == "" {
		return f, nil, true
	}
	entry, ok := matchService(product)
	if !ok {
		return f, nil, true
	}
	older, ok := versionLess(version, entry.ver)
	if !ok || !older {
		return f, nil, true // unparseable or up-to-date → leave untouched (no guess)
	}

	f.Description = strings.TrimSpace(f.Description + fmt.Sprintf(
		"\nOutdated service: %s %s is below the minimum-safe version %s. %s — upgrade to a current release.",
		f.ToolArgs["product"], version, entry.ver, entry.reason))

	// Bump to at least medium so an outdated internet-facing service stops reading as benign "info".
	if f.Severity.Rank() < types.SeverityMedium.Rank() {
		from := f.Severity
		f.Severity = types.SeverityMedium
		return f, []types.AuditEntry{{
			FindingID:    f.ID,
			Action:       "promote",
			FromSeverity: from,
			ToSeverity:   types.SeverityMedium,
			Rule:         "service_eol::outdated-version",
			Reason:       fmt.Sprintf("%s %s < min-safe %s", product, version, entry.ver),
		}}, true
	}
	return f, nil, true
}

// matchService resolves an nmap product string to a curated entry. nmap products can carry extra words
// ("Apache httpd", "Exim smtpd"); try the full normalized string, then progressively shorter prefixes.
func matchService(product string) (minSafe, bool) {
	if e, ok := serviceMinSafe[product]; ok {
		return e, true
	}
	fields := strings.Fields(product)
	for n := len(fields); n >= 1; n-- {
		if e, ok := serviceMinSafe[strings.Join(fields[:n], " ")]; ok {
			return e, true
		}
	}
	// also try the first token alone (e.g. "openssh" from "openssh 6.6.1p1" if product included it)
	if len(fields) > 0 {
		if e, ok := serviceMinSafe[fields[0]]; ok {
			return e, true
		}
	}
	return minSafe{}, false
}

// versionLess reports whether version a is strictly older than b, comparing leading numeric dotted
// components (so "6.6.1p1" → [6 6 1], "2.4.7" → [2 4 7]). ok=false when neither side has a parseable numeric
// lead — the caller then declines to flag (never guesses on an opaque version string).
func versionLess(a, b string) (less bool, ok bool) {
	av, aok := numericParts(a)
	bv, bok := numericParts(b)
	if !aok || !bok {
		return false, false
	}
	for i := 0; i < len(av) || i < len(bv); i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			return x < y, true
		}
	}
	return false, true // equal
}

// numericParts extracts the leading numeric dotted components of a version string, stopping at the first
// non-numeric component (so a trailing "p1"/"beta" is ignored). ok=false if there is no numeric lead.
func numericParts(v string) ([]int, bool) {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// take the leading digit run of this component (handles "1p1", "0-ubuntu", "7~deb")
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		if j == 0 {
			break
		}
		n, err := strconv.Atoi(p[:j])
		if err != nil {
			break
		}
		out = append(out, n)
		if j < len(p) {
			break // non-numeric suffix → stop (e.g. "1p1" contributes 1 then stops)
		}
	}
	return out, len(out) > 0
}
