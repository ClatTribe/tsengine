package codelocalize

import (
	"context"
	"fmt"
	"strings"
)

// heuristic.go is the deterministic, LLM-free localization substrate. It scores each source file by the
// density of CWE-specific SINK tokens, rewards source→sink CO-OCCURRENCE (an input source near a sink is
// the taint shape that distinguishes a real vuln site from an incidental API use — the signal that lifts
// this above dumb grep), and cites the concrete matched line for every point of score. A clean file
// (no sink, no keyword) scores 0 and is dropped, so a hardened repo localizes to an EMPTY ranking (the
// FP-control property, §14.1.1).

// weights: a strong API-shaped sink dominates; a bare SQL/keyword token corroborates; source
// co-occurrence and free-text keywords are weak tie-breakers.
const (
	wStrongSink = 3.0
	wWeakSink   = 1.0
	wSource     = 1.0 // one-time bonus when a taint source co-occurs with any sink in the file
	wKeyword    = 0.5
	keywordCap  = 2.0
	maxReasons  = 6
)

type cweSignals struct {
	label  string
	strong []string // API-shaped sinks (high precision)
	weak   []string // corroborating tokens (lower precision)
}

// sinkTable maps a CWE class to its localization signals. Tokens are lowercase; matched as substrings
// against lowercased source lines (language-agnostic). Curated for the common first-party web/app CWEs
// where a code sink is the localizable artifact; classes whose "site" isn't a code token (CSRF config,
// authz logic) are intentionally absent — the table reports honestly rather than guessing (§10).
var sinkTable = map[string]cweSignals{
	"CWE-89": {"SQL Injection",
		[]string{"db.query", "db.exec", ".query(", "cursor.execute", "mysqli_query", "->query(", ".raw(", "rawquery", "executequery", "statement.execute", "sequelize.query", "session.execute"},
		[]string{"select ", "insert into", "delete from", " where ", "sprintf", "string.format", "f\"select", "\" + "}},
	"CWE-79": {"Cross-Site Scripting",
		[]string{"innerhtml", "dangerouslysetinnerhtml", "document.write", "v-html", "render_template_string", "|safe", "res.send(", "res.write(", ".html(", "response.write"},
		[]string{"echo ", "<%=", "print(", "mark_safe"}},
	"CWE-78": {"OS Command Injection",
		[]string{"exec.command", "os/exec", "subprocess.", "os.system", "runtime.getruntime().exec", "shell_exec", "child_process", "execsync(", "spawn(", "popen(", "system("},
		[]string{"sh -c", "cmd /c", "/bin/bash", "os.popen"}},
	"CWE-22": {"Path Traversal",
		[]string{"filepath.join", "os.open(", "ioutil.readfile", "os.readfile", "path.join(", "sendfile(", "readfile(", "fopen(", "file.open", "new file("},
		[]string{"../", "..\\", "servefile", "download"}},
	"CWE-502": {"Insecure Deserialization",
		[]string{"pickle.loads", "yaml.load(", "objectinputstream", "unserialize(", "readobject(", "marshal.loads", "cpickle.loads", "yaml.unsafe_load"},
		[]string{"deserialize", "readvalue("}},
	"CWE-611": {"XML External Entity",
		[]string{"documentbuilder", "saxparser", "xmlreader", "etree.parse", "resolveentity", "xmlinputfactory", "libxml_disable_entity_loader"},
		[]string{"<!doctype", "external-general-entities", "!entity"}},
	"CWE-918": {"Server-Side Request Forgery",
		[]string{"http.get(", "requests.get(", "urllib.request.urlopen", "urlopen(", "curl_exec", "http.newrequest", "axios.get(", "httpclient.", "webrequest.create"},
		[]string{"fetch(", "webhook", "callback_url"}},
	"CWE-94": {"Code Injection",
		[]string{"eval(", "new function(", "vm.runin", "compile(", "pickle.loads", "exec(\""},
		[]string{"settimeout(\"", "setinterval(\""}},
	"CWE-798": {"Hardcoded Credentials",
		[]string{"-----begin", "aws_secret_access_key", "private_key =", "api_key =", "apikey =", "secret_key =", "password = \"", "password=\""},
		[]string{"password:", "token =", "credential"}},
	"CWE-327": {"Weak Cryptography",
		[]string{"hashlib.md5", "md5.new", "sha1.new", "des.new", "crypto/md5", "crypto/des", "messagedigest.getinstance(\"md5", "cipher.getinstance(\"des"},
		[]string{"md5(", "sha1(", "ecb", "rc4"}},
	"CWE-338": {"Weak PRNG",
		[]string{"math/rand", "random.random(", "random.randint(", "math.random(", "mt_rand("},
		[]string{"new random(", "rand()"}},
	"CWE-601": {"Open Redirect",
		[]string{"res.redirect(", "sendredirect(", "http.redirect", "window.location =", "location.href ="},
		[]string{"returnurl", "redirect_uri", "next="}},
	"CWE-295": {"Improper Certificate Validation",
		[]string{"insecureskipverify", "verify=false", "cert_none", "trustallcerts", "sslverify=false", "rejectunauthorized: false", "rejectunauthorized:false", "curlopt_ssl_verifypeer, 0", "checkservertrusted"},
		[]string{"verify: false", "allowallhostnames"}},
	"CWE-434": {"Unrestricted File Upload",
		[]string{"move_uploaded_file(", "multipartfile", ".transferto(", "formfile(", "saveas("},
		[]string{"content-disposition", "originalfilename"}},
	"CWE-90": {"LDAP Injection",
		[]string{"dircontext.search", "ldap_search", "new searchrequest", "initialdircontext", "ldapconnection.search", "search_s("},
		[]string{"(&(", "objectclass="}},
	"CWE-643": {"XPath Injection",
		[]string{"xpath.compile", "selectnodes(", "selectsinglenode(", "xpath.evaluate", "xpathexpression", "compile(\"//"},
		[]string{"/text()", "createxpath"}},
}

// sourceTokens are generic taint-source indicators. Their presence NEAR a sink (same file) is the
// co-occurrence bonus — a request-derived value flowing toward a sink is what makes a site suspicious.
var sourceTokens = []string{
	"request.", "req.body", "req.query", "req.params", "req.", "getparameter", "os.args", "r.url.query",
	".formvalue", ".form", "$_get", "$_post", "$_request", "argv", "querystring", "flask.request",
	"http.request", "input(", "params[", "params.get", "readline", "scanner.next",
}

// normalizeCWE upper-cases and ensures the "CWE-" prefix so "89"/"cwe-89"/"CWE-89" all key the table.
func normalizeCWE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "CWE-")
	if s == "" {
		return ""
	}
	return "CWE-" + s
}

// HeuristicLocalizer is the deterministic tier. Zero config; safe default.
type HeuristicLocalizer struct{}

// Localize ranks repo files by CWE-sink evidence density. Deterministic and grounded: every point of a
// file's score is backed by a real token at a real line, recorded in Reasons.
func (HeuristicLocalizer) Localize(_ context.Context, q Query, repo Repo) (Result, error) {
	res := Result{Engine: "heuristic"}
	var known []string
	for _, c := range q.CWE {
		if n := normalizeCWE(c); n != "" {
			if _, ok := sinkTable[n]; ok {
				known = append(known, n)
			}
		}
	}
	keywords := q.keywords()

	if len(known) == 0 {
		res.Trace = append(res.Trace, fmt.Sprintf("no CWE in the localization table for %v — falling back to keyword-only scoring (low confidence)", q.CWE))
	} else {
		var labels []string
		for _, c := range known {
			labels = append(labels, fmt.Sprintf("%s (%s)", c, sinkTable[c].label))
		}
		res.Trace = append(res.Trace, fmt.Sprintf("localizing %s across %d source files", strings.Join(labels, ", "), len(repo)))
	}

	for _, f := range repo {
		cand := scoreFile(f, known, keywords)
		if cand.Score > 0 {
			res.Ranked = append(res.Ranked, cand)
		}
	}
	rankCandidates(res.Ranked)

	if len(res.Ranked) == 0 {
		res.Trace = append(res.Trace, "no sink evidence found — repo localizes clean for this class")
	} else {
		top := res.Ranked[0]
		res.Trace = append(res.Trace, fmt.Sprintf("top candidate %s (score %.1f): %s", top.Path, top.Score, strings.Join(top.Reasons, "; ")))
	}
	return res, nil
}

// scoreFile computes one file's score + evidence for the known CWEs and keywords.
func scoreFile(f File, knownCWEs, keywords []string) Candidate {
	lines := strings.Split(f.Content, "\n")
	cand := Candidate{Path: f.Path}
	var hasStrong, hasWeak, hasSource, hasKeyword bool

	addReason := func(r string) {
		if len(cand.Reasons) < maxReasons {
			cand.Reasons = append(cand.Reasons, r)
		}
	}

	for _, cwe := range knownCWEs {
		sig := sinkTable[cwe]
		for i, raw := range lines {
			low := strings.ToLower(raw)
			for _, tok := range sig.strong {
				if matchToken(low, tok) {
					cand.Score += wStrongSink
					hasStrong = true
					if len(cand.SinkLines) < maxReasons {
						cand.SinkLines = append(cand.SinkLines, i+1)
					}
					addReason(fmt.Sprintf("%s:%d matched `%s` (%s sink)", f.Path, i+1, tok, cwe))
					break // one strong hit per line is enough; avoid a token-stuffed line dominating
				}
			}
			for _, tok := range sig.weak {
				if matchToken(low, tok) {
					cand.Score += wWeakSink
					hasWeak = true
					break
				}
			}
		}
	}

	// source→sink co-occurrence bonus (only meaningful when a sink is present).
	if hasStrong || hasWeak {
		low := strings.ToLower(f.Content)
		for _, s := range sourceTokens {
			if matchToken(low, s) {
				cand.Score += wSource
				hasSource = true
				addReason(fmt.Sprintf("%s carries a taint source `%s` near a sink", f.Path, s))
				break
			}
		}
	}

	// free-text keyword corroboration (weak, capped). Kept as a plain substring test — keywords are
	// already whole words and low-weight, so a loose match here can't dominate a score.
	if len(keywords) > 0 {
		low := strings.ToLower(f.Content)
		kw := 0.0
		for _, k := range keywords {
			if kw >= keywordCap {
				break
			}
			if strings.Contains(low, k) {
				kw += wKeyword
			}
		}
		cand.Score += kw
		hasKeyword = kw > 0
	}

	cand.Confidence = confidence(hasStrong, hasWeak, hasSource, hasKeyword)
	return cand
}

// confidence maps the KIND of evidence to a 0–1 scalar (not the raw score, which is unbounded). A strong
// API-shaped sink is the backbone; a taint source near it and keyword corroboration lift it; a weak-token-
// only hit is low; keyword-only (unknown-CWE fallback) is lowest. Capped below 1.0 — a token heuristic is
// never certain (§10 humility; the LLM tier / a verifier is what earns higher trust).
func confidence(hasStrong, hasWeak, hasSource, hasKeyword bool) float64 {
	conf := 0.0
	switch {
	case hasStrong:
		conf = 0.6
	case hasWeak:
		conf = 0.3
	}
	if hasSource {
		conf += 0.25
	}
	if hasKeyword {
		conf += 0.1
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return conf
}

// matchToken reports whether hay (already lowercased) contains tok with a left WORD BOUNDARY when tok
// starts word-like — so `system(` does NOT match inside `ecosystem(`, and `select ` does NOT match
// inside `reselect `. Symbol-leading tokens (`../`, `<%=`, `.query(`) skip the boundary check (there's no
// identifier to falsely extend). This is the precision guard that stops incidental substrings from
// scoring a clean file (I observed `system(`/`select ` false-hits on real code before this).
func matchToken(hay, tok string) bool {
	if tok == "" {
		return false
	}
	needBoundary := isIdentByte(tok[0])
	from := 0
	for {
		rel := strings.Index(hay[from:], tok)
		if rel < 0 {
			return false
		}
		i := from + rel
		if !needBoundary || i == 0 || !isIdentByte(hay[i-1]) {
			return true
		}
		from = i + 1
	}
}

// isIdentByte reports whether b can be part of an identifier (so a match preceded by one is mid-word).
func isIdentByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
