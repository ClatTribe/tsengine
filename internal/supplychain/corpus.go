package supplychain

// DefaultCorpus is the checked-in snapshot of well-documented malicious-package
// incidents — the embedded default when no refreshed corpus is configured. It is
// deliberately conservative (only widely-reported, confirmed-malicious entries)
// so a match is high-confidence. `corpus refresh` ingests the full OSSF
// malicious-packages dataset (tens of thousands of OSV MAL- records) out of band.
//
// Provenance is the public incident, not a fabricated advisory id. Versions are
// pinned for HIJACKED legitimate packages (only the malicious republish is bad);
// left empty for pure TYPOSQUATS (no version of that name should ever install).
func DefaultCorpus() []MaliciousPackage {
	return []MaliciousPackage{
		// --- npm: hijacked legitimate packages (pin the malicious versions) ---
		{Ecosystem: "npm", Name: "flatmap-stream", Versions: []string{"0.1.1"},
			Advisory: "event-stream incident 2018",
			Summary:  "Backdoor injected to steal Bitcoin wallet credentials (the event-stream supply-chain attack)."},
		{Ecosystem: "npm", Name: "ua-parser-js", Versions: []string{"0.7.29", "0.8.0", "1.0.0"},
			Advisory: "ua-parser-js hijack 2021",
			Summary:  "Maintainer account compromised; releases shipped a crypto-miner and a password/credential stealer."},
		{Ecosystem: "npm", Name: "coa", Versions: []string{"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"},
			Advisory: "coa hijack 2021", Summary: "Compromised releases shipped a credential-stealing payload."},
		{Ecosystem: "npm", Name: "rc", Versions: []string{"1.2.9", "1.3.9", "2.3.9"},
			Advisory: "rc hijack 2021", Summary: "Compromised releases shipped the same credential-stealing payload as coa."},
		{Ecosystem: "npm", Name: "node-ipc", Versions: []string{"9.2.2", "10.1.1", "10.1.2", "10.1.3"},
			Advisory: "node-ipc protestware 2022",
			Summary:  "Maintainer added geo-targeted payloads that overwrote files and/or wrote protest messages (protestware sabotage)."},
		{Ecosystem: "npm", Name: "colors", Versions: []string{"1.4.1", "1.4.44-liberty-2"},
			Advisory: "colors sabotage 2022", Summary: "Maintainer self-sabotage: an infinite loop that hangs any dependent app (DoS)."},
		{Ecosystem: "npm", Name: "faker", Versions: []string{"6.6.6"},
			Advisory: "faker sabotage 2022", Summary: "Maintainer self-sabotage release that breaks dependents (DoS)."},

		// --- pypi: typosquats (every version malicious) + hijacks ---
		{Ecosystem: "pypi", Name: "ctx", Versions: []string{"0.1.2", "0.2.2"},
			Advisory: "ctx hijack 2022",
			Summary:  "Hijacked package republished to exfiltrate environment variables (AWS keys) to a remote host."},
		{Ecosystem: "pypi", Name: "jeIlyfish",
			Advisory: "jeIlyfish typosquat", Summary: "Typosquat of 'jellyfish' (capital I for l) that stole SSH/GPG keys."},
		{Ecosystem: "pypi", Name: "python3-dateutil",
			Advisory: "python3-dateutil typosquat", Summary: "Typosquat of 'python-dateutil' paired with the jeIlyfish credential stealer."},
		{Ecosystem: "pypi", Name: "request",
			Advisory: "request typosquat", Summary: "Typosquat of 'requests'; known to ship data-exfiltration payloads."},
		{Ecosystem: "pypi", Name: "colourama",
			Advisory: "colourama typosquat", Summary: "Typosquat of 'colorama'; a clipboard hijacker that swaps cryptocurrency addresses."},
	}
}
