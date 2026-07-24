package toolselect

import (
	"strings"
	"testing"
)

// webagentCatalog models the REAL offensive-agent library (internal/webagent/tools.go, 23 tools) as
// selection data: CORE always-on + the exploit/probe specialists with curated tags. This is exactly
// the catalog the agent would hand toolselect each turn; the tests prove the right ~handful surfaces
// per task instead of all 23.
func webagentCatalog() *Catalog {
	core := func(n, d string) Tool { return Tool{Name: n, Description: d, AlwaysOn: true} }
	return NewCatalog([]Tool{
		core("send_request", "fire one HTTP request and read deterministic indicators"),
		core("record_finding", "commit a grounded vulnerability finding"),
		core("finish", "end the engagement with an executive summary"),
		core("dispatch_oss", "gateway to sandbox OSS specialists: sqlmap wpscan nuclei ffuf hydra padbuster"),
		{Name: "list_routes", Description: "the known request surface", Tags: []string{"recon", "routes", "surface"}},
		{Name: "discover_content", Description: "brute hidden unlinked paths and params", Tags: []string{"recon", "content", "discovery", "hidden", "params"}},
		{Name: "graphql_introspect", Description: "introspect a GraphQL schema", Tags: []string{"graphql", "schema", "api", "introspection"}},
		{Name: "browser_render", Description: "render a page in a real headless browser to prove DOM XSS", Tags: []string{"xss", "dom", "browser", "javascript"}},
		{Name: "sqli_bool_probe", Description: "ground a boolean blind SQL injection differential", Tags: []string{"sqli", "sql", "injection", "blind", "boolean"}},
		{Name: "nosqli_probe", Description: "ground a NoSQL MongoDB injection with operator payload", Tags: []string{"nosqli", "mongodb", "injection", "operator"}},
		{Name: "bola_probe", Description: "ground an IDOR/BOLA broken object level authorization differential", Tags: []string{"bola", "idor", "authz", "authorization", "object"}},
		{Name: "privesc_probe", Description: "ground self privilege escalation / mass assignment", Tags: []string{"privesc", "privilege", "escalation", "mass", "assignment", "bfla"}},
		{Name: "session_idor_probe", Description: "ground a login-sets-session IDOR", Tags: []string{"idor", "session", "login", "authz"}},
		{Name: "tamper_probe", Description: "ground a broken access control where the server trusts a client field", Tags: []string{"tamper", "access", "control", "authz", "header"}},
		{Name: "race_probe", Description: "ground a limit-bypass TOCTOU race condition", Tags: []string{"race", "toctou", "limit", "concurrency"}},
		{Name: "jwt_crack", Description: "crack a JWT HMAC secret or detect alg none and forge a token", Tags: []string{"jwt", "token", "hmac", "forge", "session"}},
		{Name: "crack_hash", Description: "crack an unsalted MD5 SHA1 SHA256 password hash", Tags: []string{"hash", "creds", "password", "md5", "sha1"}},
		{Name: "try_default_creds", Description: "post a list of default credentials to a login endpoint", Tags: []string{"creds", "default", "login", "brute"}},
		{Name: "oob_url", Description: "mint an out of band callback URL for a blind vuln", Tags: []string{"oob", "blind", "ssrf", "callback", "interactsh"}},
		{Name: "oob_check", Description: "check whether the target called your out of band URL back", Tags: []string{"oob", "blind", "ssrf", "callback"}},
		{Name: "confirm_exploit", Description: "re-fire the proving request to verify a finding", Tags: []string{"verify", "confirm", "reproduce"}},
		{Name: "ssh_exec", Description: "connect over SSH with leaked credentials and run one command", Tags: []string{"ssh", "creds", "lateral", "movement", "exec"}},
		{Name: "note_defense", Description: "remember a WAF or filter you hit", Tags: []string{"waf", "filter", "defense"}},
	})
}

// contains reports membership in a selection's names.
func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestSelect_TaskDrivenSubset(t *testing.T) {
	cat := webagentCatalog()
	cases := []struct {
		task     string
		mustHave []string
		mustNot  []string
	}{
		{
			task:     "prove a blind boolean SQL injection on the search parameter",
			mustHave: []string{"sqli_bool_probe", "send_request", "record_finding"},
			mustNot:  []string{"jwt_crack", "ssh_exec", "graphql_introspect", "race_probe"},
		},
		{
			task:     "the app issues JWT session tokens; forge an admin token",
			mustHave: []string{"jwt_crack"},
			mustNot:  []string{"sqli_bool_probe", "nosqli_probe", "race_probe"},
		},
		{
			task:     "check for IDOR / broken object level authorization on the orders endpoint",
			mustHave: []string{"bola_probe"},
			mustNot:  []string{"jwt_crack", "race_probe", "browser_render"},
		},
		{
			task:     "we found leaked SSH credentials in a config file; get the flag",
			mustHave: []string{"ssh_exec"},
			mustNot:  []string{"sqli_bool_probe", "graphql_introspect"},
		},
		{
			task:     "prove a reflected XSS executes in the DOM",
			mustHave: []string{"browser_render"},
			mustNot:  []string{"sqli_bool_probe", "ssh_exec"},
		},
	}
	for _, tc := range cases {
		sel := cat.Select(Query{Task: tc.task, MaxActive: 9})
		names := sel.Names()
		if len(sel.Tools) > 9 {
			t.Errorf("[%s] active set %d exceeds cap 9", tc.task, len(sel.Tools))
		}
		for _, w := range tc.mustHave {
			if !contains(names, w) {
				t.Errorf("[%s] expected %q in active set, got %v", tc.task, w, names)
			}
		}
		for _, n := range tc.mustNot {
			if contains(names, n) {
				t.Errorf("[%s] did NOT expect %q in active set, got %v", tc.task, n, names)
			}
		}
	}
}

func TestSelect_AlwaysOnAndCap(t *testing.T) {
	cat := webagentCatalog()
	sel := cat.Select(Query{Task: "sql injection", MaxActive: 6})
	names := sel.Names()
	// The 4 CORE tools are always present regardless of relevance.
	for _, core := range []string{"send_request", "record_finding", "finish", "dispatch_oss"} {
		if !contains(names, core) {
			t.Errorf("core tool %q must always be active, got %v", core, names)
		}
	}
	if len(sel.Tools) != 6 {
		t.Errorf("active set should be exactly the cap (6), got %d", len(sel.Tools))
	}
	// 23 total, 6 active → 17 withheld.
	if sel.Withheld != 17 {
		t.Errorf("withheld = %d, want 17", sel.Withheld)
	}
}

func TestSelect_IrrelevantTaskSurfacesOnlyCore(t *testing.T) {
	cat := webagentCatalog()
	// A task with no lexical overlap with any specialist → only the always-on core (no padding with
	// irrelevant specialists just to fill slots).
	sel := cat.Select(Query{Task: "zzzz qqqq wwww", MaxActive: 12})
	if len(sel.Tools) != 4 {
		t.Errorf("an off-catalog task should surface only the 4 core tools, got %v", sel.Names())
	}
}

func TestSelect_PhaseFiltering(t *testing.T) {
	order := []string{"recon", "exploit", "report"}
	cat := NewCatalog([]Tool{
		{Name: "list_routes", Description: "surface", Tags: []string{"recon"}, Phases: []string{"recon"}},
		{Name: "sqli_bool_probe", Description: "sql injection", Tags: []string{"sqli", "injection"}, Phases: []string{"exploit"}},
		{Name: "finish", Description: "end", AlwaysOn: true, Phases: []string{"report"}},
	})
	// In recon phase, the exploit-only sqli tool is ineligible even though the task mentions sql.
	sel := cat.Select(Query{Task: "sql injection recon the surface", Phase: "recon", PhaseOrder: order})
	if contains(sel.Names(), "sqli_bool_probe") {
		t.Errorf("exploit-phase tool must be hidden during recon, got %v", sel.Names())
	}
	if !contains(sel.Names(), "list_routes") {
		t.Errorf("recon tool should be eligible in recon, got %v", sel.Names())
	}
	// In exploit phase, the earlier recon tool is still eligible (later phases keep earlier caps).
	sel2 := cat.Select(Query{Task: "sql injection", Phase: "exploit", PhaseOrder: order})
	if !contains(sel2.Names(), "sqli_bool_probe") {
		t.Errorf("exploit tool should be eligible in exploit phase, got %v", sel2.Names())
	}
}

func TestSelect_Deterministic(t *testing.T) {
	cat := webagentCatalog()
	q := Query{Task: "broken object level authorization idor", MaxActive: 8}
	a := strings.Join(cat.Select(q).Names(), ",")
	for i := 0; i < 5; i++ {
		if b := strings.Join(cat.Select(q).Names(), ","); b != a {
			t.Fatalf("selection is non-deterministic: %q vs %q", a, b)
		}
	}
}
