package bench

import (
	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// localize_hard.go is the DISCRIMINATING half of the localization benchmark.
//
// WHY IT EXISTS. The original corpus (LocalizeScenarios) scores 1.00 recall@1 on the deterministic
// heuristic alone — every scenario pairs one blatant sink against decoys like `const Version = "1.2.3"`,
// so a keyword matcher wins outright. That corpus proves the substrate works, which is what it was
// built for, but it is USELESS for comparing models: with no headroom, a better model and a worse one
// both score 1.00 and the ablation reads +0.00 either way.
//
// These scenarios are built so keyword matching is actively WRONG, not merely unhelpful. Each repo
// contains several files that all touch the CWE's sink API, and the distinguishing evidence is
// semantic:
//
//   - SANITIZED DECOY — uses the same dangerous-looking API correctly (parameterized query, escaped
//     output, allowlisted path). A "contains db.Query" ranker flags it; a reader sees it is safe.
//   - INDIRECT FLOW — the taint reaches the sink through a helper or struct field, so the source and
//     the sink never appear on the same line, defeating single-line pattern matching.
//   - CROSS-FILE — the untrusted read is in one file and the sink in another; only one of the two is
//     the place a fix belongs.
//   - PLAUSIBLE-BUT-UNREACHABLE — a genuinely unsafe-looking sink whose input is a compile-time
//     constant or internal enum, i.e. not attacker-controlled.
//
// Ground truth stays SINGLE-file per scenario so recall@1 remains meaningful, and each truth file is
// the one a security engineer would actually patch.
//
// The corpus is deliberately first-party and synthetic (§14 anti-overfit): no SUT-specific identifiers,
// no copied vulnerable snippets from a public benchmark the models may have memorized.
func LocalizeHardScenarios() []LocalizeScenario {
	return []LocalizeScenario{
		{
			// CROSS-FILE. The request is parsed in handler.go; the unsafe concatenation lives in query.go,
			// which never mentions http. The fix belongs at the sink. A ranker that rewards "taint source
			// near a sink" scores the handler top and misses the file that actually needs changing.
			Name:  "sqli-cross-file-sink",
			Query: codelocalize.Query{CWE: []string{"CWE-89"}, Title: "SQL injection in reporting filter"},
			Repo: codelocalize.Repo{
				{Path: "internal/report/handler.go", Content: "" +
					"func Handle(w http.ResponseWriter, r *http.Request) {\n" +
					"  where := r.URL.Query().Get(\"where\")\n" +
					"  rows := RunFilter(where)\n" +
					"  writeRows(w, rows)\n" +
					"}\n"},
				{Path: "internal/report/query.go", Content: "" +
					"func RunFilter(clause string) *sql.Rows {\n" +
					"  rows, _ := pool.Query(\"SELECT id FROM sales WHERE \" + clause)\n" +
					"  return rows\n" +
					"}\n"},
				{Path: "internal/report/daily.go", Content: "" +
					"func Daily(org string) {\n" +
					"  pool.Query(\"SELECT id, total FROM sales WHERE org = ?\", org)\n" +
					"}\n"},
			},
			Truth: []string{"internal/report/query.go"},
		},
		{
			// The escaped renderer is the decoy; the raw one is two hops from the request.
			Name:  "xss-through-helper",
			Query: codelocalize.Query{CWE: []string{"CWE-79"}, Title: "Stored XSS in comment rendering"},
			Repo: codelocalize.Repo{
				{Path: "web/render.js", Content: "" +
					"export function safeBlock(text) {\n" +
					"  return '<div>' + escapeHTML(text) + '</div>';\n" +
					"}\n"},
				{Path: "web/comment.js", Content: "" +
					"import { rawBlock } from './widget.js';\n" +
					"export function show(comment, res) {\n" +
					"  res.send(rawBlock(comment.body));\n" +
					"}\n"},
				{Path: "web/widget.js", Content: "" +
					"export function rawBlock(text) {\n" +
					"  return '<span>' + text + '</span>';\n" +
					"}\n"},
			},
			// The fix belongs where untrusted data is handed to the raw sink.
			Truth: []string{"web/comment.js"},
		},
		{
			// Two exec sites; only one takes a request value. The other builds from a fixed list.
			// CROSS-FILE. api.go reads the request; runner.go builds the shell string. Both backup.go and
			// probe.go call exec with fixed arguments, so sink-presence alone cannot separate them.
			Name:  "cmdinjection-cross-file-sink",
			Query: codelocalize.Query{CWE: []string{"CWE-78"}, Title: "Command injection in archive tool"},
			Repo: codelocalize.Repo{
				{Path: "tools/api.go", Content: "" +
					"func ConvertHandler(r *http.Request) {\n" +
					"  Run(r.FormValue(\"opts\"))\n" +
					"}\n"},
				{Path: "tools/runner.go", Content: "" +
					"func Run(opts string) {\n" +
					"  exec.Command(\"sh\", \"-c\", \"convert \"+opts+\" out.png\").Run()\n" +
					"}\n"},
				{Path: "tools/backup.go", Content: "" +
					"var allowed = []string{\"daily\", \"weekly\"}\n" +
					"func Backup(tag int) {\n" +
					"  exec.Command(\"tar\", \"-czf\", allowed[tag]+\".tgz\", \"/data\").Run()\n" +
					"}\n"},
				{Path: "tools/probe.go", Content: "" +
					"func Probe() { exec.Command(\"uname\", \"-a\").Run() }\n"},
			},
			Truth: []string{"tools/runner.go"},
		},
		{
			// The allowlisted reader is the decoy; the tainted one resolves through a struct field.
			// CROSS-FILE plus a SANITIZED decoy. route.go holds the request; loader.go joins the untrusted
			// segment; assets.go looks similar but resolves through an allowlist map and is safe.
			Name:  "traversal-cross-file-vs-allowlist",
			Query: codelocalize.Query{CWE: []string{"CWE-22"}, Title: "Path traversal in template loader"},
			Repo: codelocalize.Repo{
				{Path: "srv/route.go", Content: "" +
					"func TemplateRoute(w http.ResponseWriter, r *http.Request) {\n" +
					"  w.Write(Load(r.URL.Query().Get(\"tpl\")))\n" +
					"}\n"},
				{Path: "srv/loader.go", Content: "" +
					"func Load(rel string) []byte {\n" +
					"  b, _ := os.ReadFile(filepath.Join(\"/srv/templates\", rel))\n" +
					"  return b\n" +
					"}\n"},
				{Path: "srv/assets.go", Content: "" +
					"var known = map[string]string{\"logo\": \"/srv/logo.png\"}\n" +
					"func Asset(name string) []byte {\n" +
					"  p, ok := known[name]\n" +
					"  if !ok { return nil }\n" +
					"  b, _ := os.ReadFile(p)\n" +
					"  return b\n" +
					"}\n"},
				{Path: "srv/cache.go", Content: "" +
					"func warm() { os.ReadFile(\"/srv/templates/index.tpl\") }\n"},
			},
			Truth: []string{"srv/loader.go"},
		},
		{
			// Both files deserialize. Only one deserializes bytes that came off the wire.
			Name:  "deser-vs-trusted-blob",
			Query: codelocalize.Query{CWE: []string{"CWE-502"}, Title: "Unsafe deserialization in session restore"},
			Repo: codelocalize.Repo{
				{Path: "app/state.go", Content: "" +
					"func loadDefaults() Config {\n" +
					"  var c Config\n" +
					"  gob.NewDecoder(bytes.NewReader(embeddedDefaults)).Decode(&c)\n" +
					"  return c\n" +
					"}\n" +
					"// embeddedDefaults is compiled in via go:embed\n"},
				{Path: "app/session.go", Content: "" +
					"func Restore(r *http.Request) Session {\n" +
					"  raw, _ := base64.StdEncoding.DecodeString(r.Header.Get(\"X-Session\"))\n" +
					"  var s Session\n" +
					"  gob.NewDecoder(bytes.NewReader(raw)).Decode(&s)\n" +
					"  return s\n" +
					"}\n"},
				{Path: "app/codec.go", Content: "" +
					"func encode(v any) []byte {\n" +
					"  var b bytes.Buffer\n" +
					"  gob.NewEncoder(&b).Encode(v)\n" +
					"  return b.Bytes()\n" +
					"}\n"},
			},
			Truth: []string{"app/session.go"},
		},
		{
			// Two outbound fetchers; one resolves a host from a request, one from config.
			Name:  "ssrf-vs-config-endpoint",
			Query: codelocalize.Query{CWE: []string{"CWE-918"}, Title: "SSRF in webhook delivery"},
			Repo: codelocalize.Repo{
				{Path: "hooks/deliver.go", Content: "" +
					"func Deliver(cfg Config, body []byte) {\n" +
					"  http.Post(cfg.Endpoint, \"application/json\", bytes.NewReader(body))\n" +
					"}\n" +
					"// cfg.Endpoint is set by an operator at boot\n"},
				{Path: "hooks/preview.go", Content: "" +
					"type Target struct{ url string }\n" +
					"func From(r *http.Request) Target {\n" +
					"  return Target{url: r.FormValue(\"callback\")}\n" +
					"}\n" +
					"func (t Target) Check() int {\n" +
					"  resp, _ := http.Get(t.url)\n" +
					"  return resp.StatusCode\n" +
					"}\n"},
				{Path: "hooks/retry.go", Content: "" +
					"func retry(u string, n int) { for i := 0; i < n; i++ { http.Get(u) } }\n" +
					"// u is always a previously-validated cfg.Endpoint\n"},
			},
			Truth: []string{"hooks/preview.go"},
		},
	}
}
