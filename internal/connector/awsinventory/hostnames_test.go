package awsinventory

import "testing"

// A hostname is tied to an instance ONLY by exact address equality — nothing that merely resembles it.
func TestAttachHostnames_ExactAddressOnly(t *testing.T) {
	raw := RawAWS{Instances: []RawInstance{
		{ID: "i-web", PublicIPAddress: "3.3.3.3", DNSNames: []string{"ec2-3-3-3-3.compute.amazonaws.com"}},
		{ID: "i-private"}, // no public address: nothing can resolve to it
	}}
	join := AttachHostnames(&raw, map[string][]string{
		"App.Acme.com.":    {"10.0.0.1", "3.3.3.3"}, // one of its addresses is the instance
		"cdn.acme.com":     {"104.16.0.1"},          // a CDN — not an instance in this account
		"staging.acme.com": {"3.3.3.30"},            // a near-miss is not a match
	})
	if join.Linked["app.acme.com"] != "i-web" {
		t.Fatalf("a hostname resolving to the instance's address must link, normalised: %+v", join)
	}
	if len(join.Unlinked) != 2 {
		t.Fatalf("the CDN host and the near-miss must both stay unlinked: %+v", join.Unlinked)
	}
	got := raw.Instances[0].DNSNames
	if len(got) != 2 || got[1] != "app.acme.com" {
		t.Fatalf("the linked hostname is added once, beside what AWS already reported: %v", got)
	}
	AttachHostnames(&raw, map[string][]string{"app.acme.com": {"3.3.3.3"}})
	if len(raw.Instances[0].DNSNames) != 2 {
		t.Fatalf("re-attaching must not duplicate: %v", raw.Instances[0].DNSNames)
	}
	if len(raw.Instances[1].DNSNames) != 0 {
		t.Fatal("an instance without a public address can never be a join target")
	}
}
