package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// THIS GUARD EXISTS BECAUSE THE SAME BUG HAPPENED FOUR TIMES IN THIS ONE FILE.
//
//	vendorProject / product              → threat-informed targeting could not match a product
//	dueDate / knownRansomwareCampaignUse → the SLA clock and the strongest severity signal
//	notes                                → the advisory URLs the docs claimed for months
//	cwes                                 → the ENTIRE compliance crosswalk, silently not running
//
// Every one had the same shape: the parser struct lists the fields someone needed at the
// time, CISA publishes more, and a field absent from the struct is dropped SILENTLY AND
// FOREVER. Nothing errors. The corpus simply carries less than the feed does, and the only
// way anyone finds out is by reading the raw JSON — which is how each of those four were
// found, one at a time, months apart.
//
// So the fix is not a fifth field. It is making an unhandled field impossible to add
// quietly: every key CISA publishes must be either PARSED or listed below as a deliberate
// skip with a reason. A new upstream field then fails this test and becomes a decision
// somebody makes on purpose.
//
// Deliberately skipped, and why:
var kevIgnoredFields = map[string]string{
	// Top-level.
	"count": "the entry count, which len(vulnerabilities) already gives us and cannot disagree with",
	"title": "the catalog's display name; catalogVersion is the field that identifies a revision",

	// Per-entry.
	"vulnerabilityName": "CISA's display name for the CVE. Every finding that reaches this enrichment " +
		"already carries the SCANNER's title, which names the affected package in the customer's own " +
		"image — more specific than a catalog label, and overwriting it would trade detail for branding",
	"shortDescription": "same reasoning as vulnerabilityName: the scanner's description is about the " +
		"instance we found, CISA's is about the CVE in general",
	"requiredAction": "92% of the catalog is one of four boilerplate variants of \"apply vendor " +
		"updates\" (measured, not assumed), which the remediation runbook already says in more " +
		"actionable form. The 8% tail is not worth a field that reads as advice on every finding",
}

// TestKEVSchemaIsFullyAccountedFor decodes a representative catalog payload generically and
// asserts every key is either parsed by kevFeed or explicitly skipped above.
func TestKEVSchemaIsFullyAccountedFor(t *testing.T) {
	// A payload carrying every field the live catalog publishes, so this guard runs in CI
	// with no network. If CISA adds a field, the LIVE test below is what notices; this one
	// pins that everything known today is accounted for.
	const payload = `{
	  "title":"CISA Catalog of Known Exploited Vulnerabilities",
	  "catalogVersion":"2026.08.21",
	  "dateReleased":"2026-08-21T12:00:00.0000Z",
	  "count":1,
	  "vulnerabilities":[{
	    "cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2",
	    "vulnerabilityName":"Apache Log4j2 Remote Code Execution Vulnerability",
	    "dateAdded":"2021-12-10","shortDescription":"Apache Log4j2 contains a vulnerability...",
	    "requiredAction":"Apply updates per vendor instructions.","dueDate":"2021-12-24",
	    "knownRansomwareCampaignUse":"Known","notes":"https://logging.apache.org/","cwes":["CWE-502"]
	  }]}`

	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &generic); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(generic["vulnerabilities"], &entries); err != nil {
		t.Fatal(err)
	}

	feedKeys := map[string]bool{}
	for k := range generic {
		feedKeys[k] = true
	}
	for _, e := range entries {
		for k := range e {
			feedKeys[k] = true
		}
	}

	parsed := parsedJSONTags(reflect.TypeOf(kevFeed{}))
	var unhandled []string
	for k := range feedKeys {
		if parsed[k] || kevIgnoredFields[k] != "" {
			continue
		}
		unhandled = append(unhandled, k)
	}
	sort.Strings(unhandled)
	if len(unhandled) > 0 {
		t.Errorf("CISA publishes %d field(s) this parser neither reads nor declares: %v\n\n"+
			"A field absent from the struct is dropped SILENTLY AND FOREVER — that is how "+
			"vendorProject, dueDate, ransomware use, the advisory URLs and the CWEs were each lost, "+
			"one at a time. Either parse it, or add it to kevIgnoredFields with the reason it is not "+
			"worth carrying.", len(unhandled), unhandled)
	}

	// The skip list must not rot either: a name listed there that the feed no longer
	// publishes is a stale exemption that would hide a real field if CISA reused the name.
	for k := range kevIgnoredFields {
		if !feedKeys[k] {
			t.Errorf("kevIgnoredFields declares %q, which this payload does not contain — "+
				"a stale exemption hides a real field if the name is ever reused", k)
		}
	}
}

// parsedJSONTags collects every json tag name in a struct, recursing into nested structs and
// slices, so the guard sees the per-entry fields inside `vulnerabilities` too.
func parsedJSONTags(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if name := strings.Split(f.Tag.Get("json"), ",")[0]; name != "" && name != "-" {
				out[name] = true
			}
			walk(f.Type)
		}
	}
	walk(t)
	return out
}

// TestKEVSchemaLive is the half the fixture cannot do: it asks the REAL catalog whether CISA
// has started publishing something we neither read nor declared.
//
// The fixture guard above pins what is known today and runs everywhere; it cannot notice an
// addition upstream, because the fixture is ours. Skipped without LIVE_FEEDS so CI stays
// hermetic — this is the check to run when a refresh looks thinner than the feed.
func TestKEVSchemaLive(t *testing.T) {
	if os.Getenv("LIVE_FEEDS") == "" {
		t.Skip("set LIVE_FEEDS=1 to check the live catalog for fields we do not handle")
	}
	body, err := httpGet(context.Background(), &http.Client{Timeout: 120 * time.Second}, KEVURL)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()

	var generic map[string]json.RawMessage
	if err := json.NewDecoder(body).Decode(&generic); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(generic["vulnerabilities"], &entries); err != nil {
		t.Fatal(err)
	}
	feedKeys := map[string]bool{}
	for k := range generic {
		feedKeys[k] = true
	}
	// Every entry, not a sample: a field CISA adds appears on new entries first, and sampling
	// the head of the list is how it would be missed for another few months.
	for _, e := range entries {
		for k := range e {
			feedKeys[k] = true
		}
	}

	parsed := parsedJSONTags(reflect.TypeOf(kevFeed{}))
	var unhandled []string
	for k := range feedKeys {
		if !parsed[k] && kevIgnoredFields[k] == "" {
			unhandled = append(unhandled, k)
		}
	}
	sort.Strings(unhandled)
	t.Logf("live catalog: %d entries, %d distinct fields", len(entries), len(feedKeys))
	if len(unhandled) > 0 {
		t.Errorf("the LIVE catalog publishes %d field(s) this parser neither reads nor declares: %v",
			len(unhandled), unhandled)
	}
}
