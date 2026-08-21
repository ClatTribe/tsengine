package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// The KEV sibling of this guard (kevschema_test.go) exists because the same field-dropping
// bug happened four times in that one parser. This one is here BEFORE it happens a fifth
// time in this parser, which publishes 26 fields of which we read five.
//
// Same contract: every key Metasploit publishes must be PARSED or declared below with the
// reason it is not worth carrying, so "we chose not to" stops being indistinguishable from
// "we forgot". Adding rank was the field-mining half of applying that lesson; this is the
// half that stops the next one being lost.
//
// Deliberately skipped, with the reasoning, so a future maintainer can revisit a call
// rather than re-derive it:
var msfIgnoredFields = map[string]string{
	// The one genuinely worth revisiting. 385 of 2,678 modules require valid credentials
	// first, and 2,160 of 2,525 CVEs have at least one UNAUTHENTICATED module — a real
	// split, and "needs creds" versus "no creds needed" is a distinction a defender ranking
	// two KEV CVEs actually uses.
	//
	// Skipped anyway because NVD's CVSS vector already carries it as PR: (Privileges
	// Required), from the authority whose job that is, and a second weaker source for one
	// fact invites the two to DISAGREE on the same finding — at which point a reader has to
	// know which to believe. WORTH RECONSIDERING IF NVD STAYS OPT-IN: it is only fetched
	// when NVDURL is set, so most deployments have no PR: at all, and for them this would
	// be the only authentication signal available.
	"post_auth": "NVD's CVSS PR: component is the authoritative version of the same fact; " +
		"revisit if NVD stays opt-in and most corpora therefore lack it",

	"check": "whether the module ships a safe check function. A real fact about " +
		"verifiability, and useless to us: we do not run msfconsole, so nothing here could act on it",
	"default_credential": "false on all 2,678 exploit modules — it flags the auxiliary " +
		"credential-checkers this parser already excludes",
	"disclosure_date": "the vulnerability's age, which KEV dateAdded and EPSS both cover " +
		"from sources closer to the question a defender is asking",
	// Operational detail for RUNNING the module — target selection, payload staging,
	// cleanup. We report that a weapon exists and how reliable it is; we are not the
	// thing firing it.
	"targets":             "operational detail for running the module",
	"platform":            "operational detail for running the module",
	"arch":                "operational detail for running the module",
	"session_types":       "operational detail for running the module",
	"rport":               "operational detail for running the module",
	"autofilter_ports":    "operational detail for running the module",
	"autofilter_services": "operational detail for running the module",
	"actions":             "operational detail for running the module",
	"aliases":             "operational detail for running the module",
	"needs_cleanup":       "operational detail for running the module",
	"is_install_path":     "operational detail for running the module",
	"author":              "module attribution, not a property of the vulnerability",
	"description": "the module's own description. Every finding reaching this enrichment " +
		"already carries the scanner's description of the instance we actually found",
	"notes":    "module caveats (stability, side effects) written for an operator about to run it",
	"path":     "the file location inside the metasploit-framework checkout",
	"mod_time": "when the module file was last edited — a fact about their repository, not ours",
	"ref_name": "the module path minus its type prefix; fullname already carries it",
}

func TestMSFSchemaIsFullyAccountedFor(t *testing.T) {
	// One module carrying every field the live metadata publishes, so this runs in CI with
	// no network. The LIVE test below is what notices an addition upstream.
	const payload = `{"exploit/multi/http/x": {
	  "fullname":"exploit/multi/http/x","name":"X","type":"exploit","rank":600,
	  "references":["CVE-2021-44228"],"disclosure_date":"2021-12-10","author":["someone"],
	  "description":"...","notes":{},"path":"/modules/x.rb","mod_time":"2026-01-01",
	  "ref_name":"multi/http/x","platform":"Linux","arch":"x86","targets":["Automatic"],
	  "session_types":["meterpreter"],"rport":8080,"autofilter_ports":[80],
	  "autofilter_services":["http"],"actions":[],"aliases":[],"check":true,
	  "post_auth":false,"default_credential":false,"needs_cleanup":true,"is_install_path":false
	}}`
	var generic map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &generic); err != nil {
		t.Fatal(err)
	}
	feedKeys := map[string]bool{}
	for _, m := range generic {
		for k := range m {
			feedKeys[k] = true
		}
	}

	parsed := parsedJSONTags(reflect.TypeOf(msfModule{}))
	var unhandled []string
	for k := range feedKeys {
		if !parsed[k] && msfIgnoredFields[k] == "" {
			unhandled = append(unhandled, k)
		}
	}
	sort.Strings(unhandled)
	if len(unhandled) > 0 {
		t.Errorf("Metasploit publishes %d field(s) this parser neither reads nor declares: %v\n\n"+
			"A field absent from msfModule is dropped silently and forever — the shape that cost the "+
			"KEV parser four fields over months. Either parse it, or add it to msfIgnoredFields with "+
			"the reason.", len(unhandled), unhandled)
	}
	for k := range msfIgnoredFields {
		if !feedKeys[k] {
			t.Errorf("msfIgnoredFields declares %q, which this payload does not contain — a stale "+
				"exemption hides a real field if the name is ever reused", k)
		}
	}
}

// The live half: the fixture is ours and cannot notice Rapid7 adding something.
func TestMSFSchemaLive(t *testing.T) {
	if os.Getenv("LIVE_FEEDS") == "" {
		t.Skip("set LIVE_FEEDS=1 to check the live metadata for fields we do not handle")
	}
	body, err := httpGet(context.Background(), &http.Client{Timeout: 120 * time.Second}, MetasploitURL)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	var generic map[string]map[string]json.RawMessage
	if err := json.NewDecoder(body).Decode(&generic); err != nil {
		t.Fatal(err)
	}
	feedKeys := map[string]bool{}
	exploits := 0
	// Every EXPLOIT module, not a sample: a new field lands on new modules first, and
	// sampling the head is how it would be missed for another few months.
	for _, m := range generic {
		var typ string
		if raw, ok := m["type"]; ok {
			_ = json.Unmarshal(raw, &typ)
		}
		if typ != "exploit" {
			continue
		}
		exploits++
		for k := range m {
			feedKeys[k] = true
		}
	}
	parsed := parsedJSONTags(reflect.TypeOf(msfModule{}))
	var unhandled []string
	for k := range feedKeys {
		if !parsed[k] && msfIgnoredFields[k] == "" {
			unhandled = append(unhandled, k)
		}
	}
	sort.Strings(unhandled)
	t.Logf("live metadata: %d exploit modules, %d distinct fields", exploits, len(feedKeys))
	if len(unhandled) > 0 {
		t.Errorf("the LIVE metadata publishes %d field(s) this parser neither reads nor declares: %v",
			len(unhandled), unhandled)
	}
}
