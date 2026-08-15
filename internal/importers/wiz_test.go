package importers

import (
	"strings"
	"testing"
	"time"
)

// Wiz is the dominant cloud-posture tool at this company size, so its export is the most valuable
// list a customer can hand over — and the one most likely to arrive in a shape we did not expect.

const wizAPI = `{"issues":[
 {"id":"i-1","severity":"CRITICAL","status":"OPEN","control":{"id":"wc-s3-public","name":"S3 bucket is publicly accessible","description":"The bucket allows public read."},"entitySnapshot":{"id":"arn:aws:s3:::acme-data","name":"acme-data","type":"BUCKET"}},
 {"id":"i-2","severity":"HIGH","status":"RESOLVED","control":{"id":"wc-old","name":"Already fixed"},"entitySnapshot":{"name":"old-vm","type":"VIRTUAL_MACHINE"}},
 {"id":"i-3","severity":"MEDIUM","status":"REJECTED","control":{"id":"wc-rej","name":"Accepted risk"},"entitySnapshot":{"name":"legacy","type":"BUCKET"}}
]}`

const wizConsole = `[
 {"id":"i-9","severity":"HIGH","status":"OPEN","control":{"id":"wc-iam","name":"Over-privileged role"},"entitySnapshot":{"name":"deploy-role","type":"IAM_ROLE"}}
]`

// Closed issues must NOT be imported. The whole point is to reduce a backlog; putting work the
// customer already dealt with back in front of them does the opposite.
func TestWiz_SkipsResolvedAndRejected(t *testing.T) {
	scan, err := FromWiz([]byte(wizAPI), "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.FindingsRaw) != 1 {
		t.Fatalf("imported %d findings, want 1 — resolved and rejected issues were not skipped: %+v",
			len(scan.FindingsRaw), scan.FindingsRaw)
	}
	if !strings.Contains(scan.FindingsRaw[0].Title, "publicly accessible") {
		t.Errorf("wrong issue survived: %q", scan.FindingsRaw[0].Title)
	}
}

// Both export shapes must work. A customer exporting from the console and one exporting from the API
// should not get different answers.
func TestWiz_AcceptsBothExportShapes(t *testing.T) {
	scan, err := FromWiz([]byte(wizConsole), "", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("the console's bare-array export was rejected: %v", err)
	}
	if len(scan.FindingsRaw) != 1 {
		t.Fatalf("bare array produced %d findings", len(scan.FindingsRaw))
	}
}

// The affected resource must survive. Without it the finding is unactionable and correlation cannot
// match it to anything we found ourselves.
func TestWiz_KeepsTheAffectedResource(t *testing.T) {
	scan, _ := FromWiz([]byte(wizAPI), "", time.Unix(0, 0))
	f := scan.FindingsRaw[0]
	if f.Endpoint != "acme-data" {
		t.Errorf("endpoint = %q, want the resource name", f.Endpoint)
	}
	if !strings.Contains(f.Description, "acme-data") {
		t.Errorf("the description does not name the affected resource: %q", f.Description)
	}
	if f.Tool != "wiz" {
		t.Errorf("tool = %q", f.Tool)
	}
}

// Auto-detection must route a Wiz export to the Wiz parser, or a customer who does not pass ?format=
// gets a confusing rejection.
func TestWiz_IsAutoDetected(t *testing.T) {
	if got := Detect([]byte(wizAPI)); got != FormatWiz {
		t.Errorf("Detect = %q, want wiz", got)
	}
	// And must not steal Snyk's or SARIF's documents.
	if got := Detect([]byte(`{"vulnerabilities":[]}`)); got != FormatSnyk {
		t.Errorf("a Snyk doc detected as %q", got)
	}
	if got := Detect([]byte(`{"runs":[]}`)); got != FormatSARIF {
		t.Errorf("a SARIF doc detected as %q", got)
	}
}

// Severity must map, not pass through. "CRITICAL" is not a severity this engine understands.
func TestWiz_NormalisesSeverity(t *testing.T) {
	scan, _ := FromWiz([]byte(wizAPI), "", time.Unix(0, 0))
	if got := string(scan.FindingsRaw[0].Severity); got != "critical" {
		t.Errorf("severity = %q, want the engine's own vocabulary", got)
	}
}

// Garbage is an error, not an empty clean import.
func TestWiz_GarbageIsAnError(t *testing.T) {
	if _, err := FromWiz([]byte("not json"), "", time.Unix(0, 0)); err == nil {
		t.Error("unparseable input was accepted as an empty import — that reads as a clean cloud account")
	}
}
