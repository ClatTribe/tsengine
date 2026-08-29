package trustcenter

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// allKinds is every DocKind the product defines. Tests iterate it rather than naming two or
// three, so a kind added later is covered by the class-level assertions below without anyone
// remembering to extend them — the failure mode where a guard keeps passing while the thing it
// guards grows past it.
var allKinds = []platform.DocKind{
	platform.DocOverview, platform.DocQuestionnaire, platform.DocSubprocessors,
	platform.DocPolicies, platform.DocComplianceReport, platform.DocVAPTReport,
	platform.DocEvidencePack, platform.DocExternal,
}

// findingBearing are the kinds whose bodies name open findings. Kept as a separate literal from
// MinVisibility's own switch on purpose: if the two are derived from each other the test proves
// nothing, and the whole point is to notice when someone widens the switch.
var findingBearing = map[platform.DocKind]bool{
	platform.DocComplianceReport: true,
	platform.DocVAPTReport:       true,
	platform.DocEvidencePack:     true,
	platform.DocExternal:         true,
}

func TestEveryKindIsCoveredByTheseTests(t *testing.T) {
	// The class-level tests below are only as good as allKinds. A kind absent from it is a kind
	// nothing here checks, which would pass silently.
	seen := map[platform.DocKind]bool{}
	for _, k := range allKinds {
		seen[k] = true
	}
	for k := range findingBearing {
		if !seen[k] {
			t.Errorf("%q is finding-bearing but missing from allKinds, so no test covers it", k)
		}
	}
	if len(allKinds) != len(defaultTitles) {
		t.Errorf("allKinds has %d entries but %d kinds have default titles — one list has grown past the other, "+
			"so some kind is either untested or unnamed on the page", len(allKinds), len(defaultTitles))
	}
}

func TestFindingBearingDocumentsCanNeverBePublic(t *testing.T) {
	// THE central refusal. A compliance report or a VAPT report is a list of what is currently
	// broken and where; published, it is a roadmap. The owner must not be able to reach that
	// state through the config, so this is checked for every kind rather than for the two
	// someone happened to think of.
	for _, k := range allKinds {
		got, clamped, why := ClampVisibility(k, platform.VisPublic)
		if findingBearing[k] {
			if got != platform.VisGated || !clamped {
				t.Errorf("%s: asked for public, got %q clamped=%v — this document names open findings", k, got, clamped)
			}
			if why == "" {
				t.Errorf("%s: clamped with no reason; the owner would see the setting silently not take effect", k)
			}
			continue
		}
		if got != platform.VisPublic || clamped {
			t.Errorf("%s: public is legitimate for this kind but was clamped to %q (%s)", k, got, why)
		}
	}
}

func TestPrivateIsAlwaysAllowed(t *testing.T) {
	// Withdrawal must never be blocked by a minimum: private is stricter than any gate, and a
	// tenant has to be able to pull a document immediately.
	for _, k := range allKinds {
		if got, clamped, _ := ClampVisibility(k, platform.VisPrivate); got != platform.VisPrivate || clamped {
			t.Errorf("%s: private was altered to %q", k, got)
		}
	}
}

func TestUnknownVisibilityFailsClosed(t *testing.T) {
	got, clamped, why := ClampVisibility(platform.DocSubprocessors, platform.Visibility("publik"))
	if got != platform.VisGated || !clamped {
		t.Fatalf("a visibility we do not recognise must fail closed to gated, got %q clamped=%v", got, clamped)
	}
	if why == "" {
		t.Error("no reason given")
	}
}

func TestNormalizeConfigClampsAndReports(t *testing.T) {
	cfg, corr := NormalizeConfig(platform.TrustCenterConfig{
		Documents: []platform.TrustDocument{
			{Kind: platform.DocVAPTReport, Visibility: platform.VisPublic},
		},
	})
	if len(cfg.Documents) != 1 || cfg.Documents[0].Visibility != platform.VisGated {
		t.Fatalf("VAPT report not clamped: %+v", cfg.Documents)
	}
	if len(corr) == 0 {
		t.Fatal("clamped without telling the owner — they would believe the report is public")
	}
	if !strings.Contains(corr[0].Reason, "roadmap") {
		t.Errorf("correction should say WHY, got %q", corr[0].Reason)
	}
}

func TestNormalizeConfigRefusesWildcardAutoApprove(t *testing.T) {
	// Auto-approving everyone is publishing wearing an access log. The log would fill with names
	// nobody checked, which is worse than an open document because it looks reviewed.
	for _, pattern := range []string{"*", "*.com", "@*"} {
		cfg, corr := NormalizeConfig(platform.TrustCenterConfig{AutoApproveDomains: []string{pattern}})
		if len(cfg.AutoApproveDomains) != 0 {
			t.Errorf("%q survived normalisation: %v", pattern, cfg.AutoApproveDomains)
		}
		if len(corr) == 0 {
			t.Errorf("%q was dropped silently", pattern)
		}
	}
}

func TestNormalizeConfigDomainHygiene(t *testing.T) {
	cfg, _ := NormalizeConfig(platform.TrustCenterConfig{
		AutoApproveDomains: []string{"@ACME.com", "acme.com", " nope ", "buyer.example"},
	})
	want := []string{"acme.com", "buyer.example"}
	if len(cfg.AutoApproveDomains) != len(want) {
		t.Fatalf("got %v, want %v", cfg.AutoApproveDomains, want)
	}
	for i, d := range want {
		if cfg.AutoApproveDomains[i] != d {
			t.Errorf("[%d] got %q want %q", i, cfg.AutoApproveDomains[i], d)
		}
	}
}

func TestNormalizeConfigExternalLinks(t *testing.T) {
	cases := []struct {
		name string
		url  string
		keep bool
	}{
		{"https kept", "https://trust.acme.com/soc2.pdf", true},
		{"http refused", "http://trust.acme.com/soc2.pdf", false},
		{"empty refused", "", false},
		{"relative refused", "/soc2.pdf", false},
		{"scheme-less refused", "trust.acme.com/soc2.pdf", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, corr := NormalizeConfig(platform.TrustCenterConfig{
				Documents: []platform.TrustDocument{{Kind: platform.DocExternal, Visibility: platform.VisGated, URL: c.url}},
			})
			if c.keep {
				if len(cfg.Documents) != 1 {
					t.Fatalf("dropped a valid https link: %v", corr)
				}
				return
			}
			if len(cfg.Documents) != 0 {
				t.Fatalf("kept an unusable link %q", c.url)
			}
			if len(corr) == 0 {
				t.Error("dropped silently — the owner sees a document that is not there")
			}
		})
	}
}

func TestGeneratedDocumentCannotCarryALink(t *testing.T) {
	// A generated row is labelled "generated from live posture". Letting a URL ride on it would
	// send the reader somewhere else entirely while the label still made our claim about it.
	cfg, corr := NormalizeConfig(platform.TrustCenterConfig{
		Documents: []platform.TrustDocument{{
			Kind: platform.DocQuestionnaire, Visibility: platform.VisPublic, URL: "https://elsewhere.example/q",
		}},
	})
	if len(cfg.Documents) != 1 {
		t.Fatalf("document dropped entirely: %v", corr)
	}
	if cfg.Documents[0].URL != "" {
		t.Errorf("link survived on a generated document: %q", cfg.Documents[0].URL)
	}
	if len(corr) == 0 {
		t.Error("stripped silently")
	}
}

func TestGrantTTLIsBoundedInBothDirections(t *testing.T) {
	if got := GrantTTL(platform.TrustCenterConfig{}); got != DefaultGrantTTL {
		// 0 must mean "unset", never "forever" — the same permanence defect as an
		// un-revocable share link, one level in.
		t.Errorf("unset TTL resolved to %v, want the default %v", got, DefaultGrantTTL)
	}
	cfg, corr := NormalizeConfig(platform.TrustCenterConfig{GrantTTLHours: 24 * 365 * 5})
	if time.Duration(cfg.GrantTTLHours)*time.Hour != MaxGrantTTL {
		t.Errorf("five years survived: %d hours", cfg.GrantTTLHours)
	}
	if len(corr) == 0 {
		t.Error("capped silently")
	}
	if got := GrantTTL(platform.TrustCenterConfig{GrantTTLHours: -5}); got != DefaultGrantTTL {
		t.Errorf("negative TTL gave %v", got)
	}
}

func TestAutoApprovesMatchesTheDomainExactly(t *testing.T) {
	// Suffix matching here would decide who reads a penetration-test report. "notacme.com" ends
	// with "acme.com" and "acme.com.attacker.example" begins with it; both are strangers.
	cfg := platform.TrustCenterConfig{AutoApproveDomains: []string{"acme.com"}}
	for _, email := range []string{"jane@acme.com", "JANE@ACME.COM"} {
		if !AutoApproves(cfg, email) {
			t.Errorf("%q should be auto-approved", email)
		}
	}
	for _, email := range []string{
		"eve@notacme.com", "eve@acme.com.attacker.example", "eve@acme.co", "eve@evil.com",
		"nodomain", "trailing@", "",
	} {
		if AutoApproves(cfg, email) {
			t.Errorf("%q must NOT be auto-approved", email)
		}
	}
}

func TestCatalogDropsUnavailableDocuments(t *testing.T) {
	// A locked row asserts the document exists and is merely withheld. On a page whose entire
	// job is to be believed by someone who cannot check, that assertion has to be earned.
	cfg := platform.TrustCenterConfig{Documents: []platform.TrustDocument{
		{Kind: platform.DocVAPTReport, Visibility: platform.VisGated},
		{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic},
	}}
	got := Catalog(cfg, Availability{"subprocessors": true}, false)
	if len(got) != 1 || got[0].Kind != platform.DocSubprocessors {
		t.Fatalf("unavailable document was listed: %+v", got)
	}
}

func TestCatalogGatesWithoutHiding(t *testing.T) {
	cfg := platform.TrustCenterConfig{Documents: []platform.TrustDocument{
		{Kind: platform.DocVAPTReport, Visibility: platform.VisGated},
		{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic},
		{Kind: platform.DocQuestionnaire, Visibility: platform.VisPrivate},
	}}
	avail := Availability{"vapt_report": true, "subprocessors": true, "questionnaire": true}

	ungated := Catalog(cfg, avail, false)
	if len(ungated) != 2 {
		t.Fatalf("want the private one hidden and the other two listed, got %d: %+v", len(ungated), ungated)
	}
	byKind := map[platform.DocKind]Entry{}
	for _, e := range ungated {
		byKind[e.Kind] = e
	}
	if byKind[platform.DocVAPTReport].Readable {
		t.Error("gated report readable without a grant")
	}
	if !byKind[platform.DocSubprocessors].Readable {
		t.Error("public document not readable")
	}
	if _, listed := byKind[platform.DocQuestionnaire]; listed {
		t.Error("a private document was listed")
	}

	granted := Catalog(cfg, avail, true)
	for _, e := range granted {
		if e.Kind == platform.DocVAPTReport && !e.Readable {
			t.Error("granted visitor still cannot read the gated report")
		}
	}
}

func TestCatalogWithholdsExternalURLUntilReadable(t *testing.T) {
	// The URL IS the document for an external row. Listing it on a locked row would make the
	// gate decorative — anyone could read the listing and follow the link.
	cfg := platform.TrustCenterConfig{Documents: []platform.TrustDocument{
		{Kind: platform.DocExternal, Visibility: platform.VisGated, URL: "https://trust.acme.com/soc2.pdf"},
	}}
	avail := Availability{"external": true}
	if u := Catalog(cfg, avail, false)[0].URL; u != "" {
		t.Fatalf("locked row leaked its URL: %q", u)
	}
	if u := Catalog(cfg, avail, true)[0].URL; u == "" {
		t.Fatal("granted visitor got no URL, so the document is unreachable")
	}
}

func TestFindAgreesWithCatalog(t *testing.T) {
	// The listing and the fetch are separate code paths reading the same config; the failure
	// worth guarding is a row that renders locked while the endpoint behind it serves anyway.
	cfg := platform.TrustCenterConfig{Documents: []platform.TrustDocument{
		{Kind: platform.DocVAPTReport, Visibility: platform.VisGated},
		{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic},
		{Kind: platform.DocQuestionnaire, Visibility: platform.VisPrivate},
		{Kind: platform.DocComplianceReport, Visibility: platform.VisGated, Framework: "soc2"},
	}}
	avail := Availability{"vapt_report": true, "subprocessors": true, "questionnaire": true, "compliance_report/soc2": true}

	for _, granted := range []bool{false, true} {
		readable := map[string]bool{}
		for _, e := range Catalog(cfg, avail, granted) {
			if e.Readable {
				readable[string(e.Kind)+"|"+e.Framework] = true
			}
		}
		for _, d := range cfg.Documents {
			_, ok := Find(cfg, d.Kind, d.Framework, avail, granted)
			if ok != readable[string(d.Kind)+"|"+d.Framework] {
				t.Errorf("granted=%v %s: Find says %v, Catalog says %v", granted, DocumentKey(d), ok, !ok)
			}
		}
	}
}

func TestFindRefusesAnUnconfiguredDocument(t *testing.T) {
	// Availability alone must not be enough: a document the tenant never offered is not on
	// offer, however producible it is.
	cfg := platform.TrustCenterConfig{Documents: []platform.TrustDocument{
		{Kind: platform.DocSubprocessors, Visibility: platform.VisPublic},
	}}
	if _, ok := Find(cfg, platform.DocVAPTReport, "", Availability{"vapt_report": true}, true); ok {
		t.Fatal("served a document that was never configured")
	}
}

func TestGrantedChecksEveryCondition(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	live := platform.TrustAccessRequest{
		Status: platform.TrustReqApproved, ExpiresAt: now.Add(time.Hour), NDAAcceptedAt: now.Add(-time.Hour),
	}
	if !live.Granted(true, now) {
		t.Fatal("a live approved grant with the NDA accepted should be granted")
	}
	cases := []struct {
		name string
		mut  func(platform.TrustAccessRequest) platform.TrustAccessRequest
		nda  bool
	}{
		{"pending", func(r platform.TrustAccessRequest) platform.TrustAccessRequest {
			r.Status = platform.TrustReqPending
			return r
		}, true},
		{"denied", func(r platform.TrustAccessRequest) platform.TrustAccessRequest {
			r.Status = platform.TrustReqDenied
			return r
		}, true},
		{"revoked", func(r platform.TrustAccessRequest) platform.TrustAccessRequest {
			r.Revoked = true
			return r
		}, true},
		{"expired", func(r platform.TrustAccessRequest) platform.TrustAccessRequest {
			r.ExpiresAt = now.Add(-time.Second)
			return r
		}, true},
		{"nda outstanding", func(r platform.TrustAccessRequest) platform.TrustAccessRequest {
			r.NDAAcceptedAt = time.Time{}
			return r
		}, true},
	}
	for _, c := range cases {
		if c.mut(live).Granted(c.nda, now) {
			t.Errorf("%s: still granted", c.name)
		}
	}
	// Expiry is exclusive at the boundary: the instant it expires, it has expired.
	atBoundary := live
	atBoundary.ExpiresAt = now
	if atBoundary.Granted(true, now) {
		t.Error("a grant expiring exactly now is still granted")
	}
	// With no NDA configured, an un-accepted NDA is not a barrier.
	noNDA := live
	noNDA.NDAAcceptedAt = time.Time{}
	if !noNDA.Granted(false, now) {
		t.Error("tenant requires no NDA, yet access was refused for want of one")
	}
}

func TestNDAHashPinsTheExactText(t *testing.T) {
	// "They accepted an NDA" is worth nothing later if the terms were editable and we recorded
	// only a boolean. The digest is what makes the acceptance checkable.
	a := NDAHash("You agree to keep this confidential.")
	b := NDAHash("You agree to keep this confidential, except when you don't.")
	if a == b {
		t.Fatal("two different agreements hash the same")
	}
	if NDAHash("  same text  ") != NDAHash("same text") {
		t.Error("surrounding whitespace changed the digest, so a cosmetic edit would look like new terms")
	}
	if len(a) != 64 {
		t.Errorf("want a sha-256 hex digest, got %d chars", len(a))
	}
}

func TestAccessTokenIsRandomAndStoredOnlyAsADigest(t *testing.T) {
	tok1, hash1, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	tok2, hash2, _ := NewAccessToken()
	if tok1 == tok2 || hash1 == hash2 {
		t.Fatal("two tokens came out identical")
	}
	if HashToken(tok1) != hash1 {
		t.Error("the stored digest does not verify the token it was made from")
	}
	if strings.Contains(hash1, tok1) || strings.Contains(tok1, hash1) {
		t.Error("the digest and the token share material; a store dump would yield access")
	}
	if len(tok1) < 40 {
		t.Errorf("token is only %d chars — too short to resist guessing", len(tok1))
	}
}

func TestApproveAndDeny(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := platform.TrustCenterConfig{GrantTTLHours: 48}
	req := platform.TrustAccessRequest{ID: "r1", Status: platform.TrustReqPending}

	ok := Approve(cfg, req, "dana@vendor.example", false, now)
	if ok.Status != platform.TrustReqApproved || ok.DecidedBy != "dana@vendor.example" || ok.AutoApproved {
		t.Fatalf("approve: %+v", ok)
	}
	if want := now.Add(48 * time.Hour); !ok.ExpiresAt.Equal(want) {
		t.Errorf("expiry %v, want %v", ok.ExpiresAt, want)
	}

	auto := Approve(cfg, req, "", true, now)
	if !auto.AutoApproved || auto.DecidedBy != "" {
		// A rule approving is not a person approving, and filling in a plausible name would
		// make the log claim a review that never happened.
		t.Errorf("auto-approval invented a decider: %+v", auto)
	}

	no := Deny(req, "dana@vendor.example", now)
	if no.Status != platform.TrustReqDenied || no.TokenHash != "" || !no.ExpiresAt.IsZero() {
		t.Errorf("deny left a usable grant behind: %+v", no)
	}
}

func TestRecordViewIsBounded(t *testing.T) {
	now := time.Now()
	req := platform.TrustAccessRequest{ID: "r1"}
	for i := 0; i < MaxViewLog+50; i++ {
		req = RecordView(req, platform.DocVAPTReport, "", now)
	}
	if len(req.Views) != MaxViewLog {
		t.Fatalf("view log grew to %d, cap is %d", len(req.Views), MaxViewLog)
	}
}

func TestPendingFirst(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := old.Add(48 * time.Hour)
	got := PendingFirst([]platform.TrustAccessRequest{
		{ID: "approved-new", Status: platform.TrustReqApproved, RequestedAt: newer},
		{ID: "pending-old", Status: platform.TrustReqPending, RequestedAt: old},
	})
	if got[0].ID != "pending-old" {
		// A pending request is somebody's evaluation sitting still; recency does not outrank it.
		t.Errorf("want the pending one first, got %q", got[0].ID)
	}
}

func TestWatermarkNamesTheRecipientAndTheMoment(t *testing.T) {
	at := time.Date(2026, 8, 26, 9, 30, 0, 0, time.UTC)
	w := Watermark("Northwind", "jane@acme.com", at)
	for _, want := range []string{"jane@acme.com", "Northwind", "2026"} {
		if !strings.Contains(w, want) {
			t.Errorf("watermark missing %q: %s", want, w)
		}
	}
	// The date is the honest half: a copy read months later describes posture that has moved on,
	// and the document must say so rather than reading as a standing certificate.
	if !strings.Contains(w, "not a fixed report") {
		t.Errorf("watermark does not warn that the posture is live: %s", w)
	}
	if anon := Watermark("Northwind", "", at); strings.Contains(anon, "  ") {
		t.Errorf("empty recipient left a hole: %q", anon)
	}
}
