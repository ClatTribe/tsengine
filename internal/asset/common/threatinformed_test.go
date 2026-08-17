package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/threatinformed"
	// nuclei registers itself via init(); the dispatch resolves it from the
	// global tool registry (in production internal/toolsbundle does this).
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A corpus file in the same byte shape the L1.5 hook consumes (bare
// map[CVE]Entry). CVE-2021-41773 is KEV-listed against Apache HTTP Server.
const corpusJSON = `{
  "CVE-2021-41773": {"kev": {"listed": true, "vendor": "Apache", "product": "HTTP Server"}, "epss": {"score": 0.94}},
  "CVE-2099-0000": {"kev": {"listed": true, "vendor": "Totally", "product": "Unrelated Thing"}},
  "CVE-2000-1111": {"cvss": 7.5}
}`

func writeCorpus(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "threat_intel.json")
	if err := os.WriteFile(p, []byte(corpusJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// nmap-style finding: the grounded product/version signal.
func nmapFinding(product, version, endpoint string) types.Finding {
	return types.Finding{
		Tool:     "nmap",
		Endpoint: endpoint,
		ToolArgs: map[string]string{"product": product, "version": version, "port": "80"},
	}
}

// The wired path: observed Apache + a KEV entry for Apache HTTP Server ⇒ a
// single bounded nuclei dispatch running exactly that CVE template.
func TestThreatInformedEscalation_TargetsKEVMatchedProduct(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, writeCorpus(t))
	got := ThreatInformedEscalation([]types.Finding{nmapFinding("Apache httpd", "2.4.49", "http://h:80")})
	if len(got) != 1 {
		t.Fatalf("want exactly 1 batched nuclei dispatch, got %d", len(got))
	}
	d := got[0]
	if d.Tool == nil || d.Tool.Name() != "nuclei" {
		t.Fatalf("dispatch should target nuclei, got %+v", d.Tool)
	}
	ids, _ := d.Args["id"].(string)
	if !strings.Contains(ids, "CVE-2021-41773") {
		t.Errorf("should probe the KEV-matched CVE, got id=%q", ids)
	}
	// §10: the unrelated-product KEV entry must NOT be probed.
	if strings.Contains(ids, "CVE-2099-0000") {
		t.Errorf("must not probe a CVE whose product was never observed: id=%q", ids)
	}
	// ...nor the CVE with no exploitation signal at all.
	if strings.Contains(ids, "CVE-2000-1111") {
		t.Errorf("must not probe a CVE with no KEV/EPSS/exploit signal: id=%q", ids)
	}
	if d.EscalatedFrom == "" {
		t.Error("dispatch must carry escalation provenance for the audit trail")
	}
}

// No corpus configured ⇒ graceful no-op (targeting is an enhancement, never a
// scan failure).
func TestThreatInformedEscalation_NoCorpusIsNoOp(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, "")
	if got := ThreatInformedEscalation([]types.Finding{nmapFinding("Apache httpd", "2.4.49", "http://h")}); got != nil {
		t.Fatalf("no corpus must yield no dispatches, got %+v", got)
	}
}

// A malformed/missing corpus file must also degrade, not error out.
func TestThreatInformedEscalation_BadCorpusDegrades(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, filepath.Join(t.TempDir(), "does-not-exist.json"))
	if got := ThreatInformedEscalation([]types.Finding{nmapFinding("Apache httpd", "", "http://h")}); got != nil {
		t.Fatalf("unreadable corpus must degrade to no dispatches, got %+v", got)
	}
}

// No observed product ⇒ nothing to target (§10: no guessing what runs here).
func TestThreatInformedEscalation_NoProductObservedIsNoOp(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, writeCorpus(t))
	bare := types.Finding{Tool: "nmap", Endpoint: "http://h", ToolArgs: map[string]string{}}
	if got := ThreatInformedEscalation([]types.Finding{bare}); got != nil {
		t.Fatalf("no product observed must yield no dispatches, got %+v", got)
	}
}

// WEB path: httpx reports the stack in ToolArgs["webserver"] ("Apache/2.4.49")
// and ["tech"]. Targeting must work off that, splitting the banner because KEV
// catalogs the product name alone.
func TestThreatInformedEscalation_WebHttpxSignalIsTargeted(t *testing.T) {
	t.Setenv(threatinformed.CorpusEnv, writeCorpus(t))
	httpxFinding := types.Finding{
		Tool:     "httpx",
		Endpoint: "https://site/",
		ToolArgs: map[string]string{"status": "200", "webserver": "Apache/2.4.49", "tech": "PHP,WordPress"},
	}
	got := ThreatInformedEscalation([]types.Finding{httpxFinding})
	if len(got) != 1 {
		t.Fatalf("httpx webserver signal should drive a targeted probe, got %d dispatches", len(got))
	}
	ids, _ := got[0].Args["id"].(string)
	if !strings.Contains(ids, "CVE-2021-41773") {
		t.Errorf("should probe the KEV CVE for the fingerprinted server, got id=%q", ids)
	}
	if tgt, _ := got[0].Args["target"].(string); tgt != "https://site/" {
		t.Errorf("probe should target the observed URL, got %q", tgt)
	}
}

func TestObservationsFromFindings_ReadsAllRealToolShapes(t *testing.T) {
	in := []types.Finding{
		// httpx: banner carries product/version together + a tech list.
		{Tool: "httpx", Endpoint: "https://s/", ToolArgs: map[string]string{"webserver": "nginx/1.18.0", "tech": "PHP,WordPress"}},
		// grype/syft: package coordinates.
		{Tool: "grype", Endpoint: "img [openssl@1.1.1k]", ToolArgs: map[string]string{"pkg": "openssl", "installed_version": "1.1.1k"}},
	}
	got := ObservationsFromFindings(in)
	byProduct := map[string]threatinformed.Observation{}
	for _, o := range got {
		byProduct[o.Product] = o
	}
	if o, ok := byProduct["nginx"]; !ok || o.Version != "1.18.0" {
		t.Errorf("httpx banner should split into product+version, got %+v", byProduct)
	}
	for _, want := range []string{"PHP", "WordPress"} {
		if _, ok := byProduct[want]; !ok {
			t.Errorf("tech list entry %q should become an observation; got %v", want, keys(byProduct))
		}
	}
	if o, ok := byProduct["openssl"]; !ok || o.Version != "1.1.1k" {
		t.Errorf("grype pkg/installed_version should be read, got %+v", byProduct)
	}
}

func keys(m map[string]threatinformed.Observation) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestObservationsFromFindings_DedupesAndParsesPort(t *testing.T) {
	in := []types.Finding{
		nmapFinding("OpenSSH", "8.9p1", "tcp://h:22"),
		nmapFinding("OpenSSH", "8.9p1", "tcp://h:22"), // dup → collapsed
		nmapFinding("nginx", "1.18.0", "http://h"),
		{Tool: "nmap", ToolArgs: map[string]string{}}, // no product → skipped
	}
	got := ObservationsFromFindings(in)
	if len(got) != 2 {
		t.Fatalf("want 2 deduped observations, got %d: %+v", len(got), got)
	}
	if got[0].Product != "OpenSSH" || got[0].Version != "8.9p1" {
		t.Errorf("observation[0] = %+v", got[0])
	}
	if got[0].Port != 80 { // from ToolArgs["port"]
		t.Errorf("port should be parsed from ToolArgs, got %d", got[0].Port)
	}
}
