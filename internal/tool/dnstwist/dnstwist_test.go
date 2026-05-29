package dnstwist

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_RegisteredLookalikes(t *testing.T) {
	blob := []byte(`[
	  {"fuzzer":"*original","domain":"example.com","dns_a":["1.2.3.4"]},
	  {"fuzzer":"homoglyph","domain":"examp1e.com","dns_a":["9.9.9.9"],"dns_mx":["mail.examp1e.com"]},
	  {"fuzzer":"tld-swap","domain":"example.net","dns_a":["8.8.8.8"]},
	  {"fuzzer":"addition","domain":"examplee.com"}
	]`)
	out := parse(blob, "example.com")
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2 (original + unresolved dropped)", len(out))
	}
	bySev := map[types.Severity]string{}
	for _, f := range out {
		bySev[f.Severity] = f.Endpoint
	}
	// Look-alike WITH MX → medium (can phish via email); without → low.
	if bySev[types.SeverityMedium] != "examp1e.com" {
		t.Errorf("MX look-alike should be medium: %v", bySev)
	}
	if bySev[types.SeverityLow] != "example.net" {
		t.Errorf("no-MX look-alike should be low: %v", bySev)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil, "x.com") != nil {
		t.Error("nil expected")
	}
}

func TestDNSTwist_Identity(t *testing.T) {
	if _, ok := tool.Get("dnstwist"); !ok {
		t.Error("dnstwist not registered")
	}
}
