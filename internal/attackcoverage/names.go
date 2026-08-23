package attackcoverage

// Names are the published MITRE ATT&CK names for the techniques tsengine's own tools declare.
//
// TRANSCRIBED, not derived: we do not ship the ATT&CK catalogue, so these are copied from MITRE's
// published technique list. A missing entry renders the bare ID rather than a guess — an invented
// technique name in a security report is the kind of confident-and-wrong this codebase exists to
// avoid, and an ID alone is honestly incomplete instead.
//
// TestEveryDeclaredTechniqueHasAName fails when a tool declares a technique with no entry here, so
// adding a wrapper forces someone to look the real name up rather than shipping a bare ID silently.
var Names = map[string]string{
	"T1027":     "Obfuscated Files or Information",
	"T1046":     "Network Service Discovery",
	"T1059":     "Command and Scripting Interpreter",
	"T1059.007": "Command and Scripting Interpreter: JavaScript",
	"T1069.003": "Permission Groups Discovery: Cloud Groups",
	"T1078":     "Valid Accounts",
	"T1078.001": "Valid Accounts: Default Accounts",
	"T1078.004": "Valid Accounts: Cloud Accounts",
	"T1083":     "File and Directory Discovery",
	"T1098":     "Account Manipulation",
	"T1110.001": "Brute Force: Password Guessing",
	"T1190":     "Exploit Public-Facing Application",
	"T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
	"T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
	"T1406":     "Obfuscated Files or Information (Mobile)",
	"T1444":     "Masquerade as Legitimate Application (Mobile)",
	"T1530":     "Data from Cloud Storage",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Unsecured Credentials: Credentials In Files",
	"T1566":     "Phishing",
	"T1580":     "Cloud Infrastructure Discovery",
	"T1583.001": "Acquire Infrastructure: Domains",
	"T1590.005": "Gather Victim Network Information: IP Addresses",
	"T1592":     "Gather Victim Host Information",
	"T1595":     "Active Scanning",
	"T1595.002": "Active Scanning: Vulnerability Scanning",
	"T1595.003": "Active Scanning: Wordlist Scanning",
	"T1600":     "Weaken Encryption",
	"T1610":     "Deploy Container",
	"T1633":     "Virtualization/Sandbox Evasion (Mobile)",
}
