package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

const importBurp = `<?xml version="1.0"?>
<issues burpVersion="2024.1.1">
  <issue><type>1049088</type><name>SQL injection</name><host>https://shop.acme.example</host>
    <path>/search</path><severity>High</severity><confidence>Firm</confidence></issue>
  <issue><type>5245952</type><name>Email addresses disclosed</name><host>https://shop.acme.example</host>
    <path>/contact</path><severity>Information</severity><confidence>Certain</confidence></issue>
  <issue><type>5245953</type><name>Robots.txt file</name><host>https://shop.acme.example</host>
    <path>/robots.txt</path><severity>Information</severity><confidence>Certain</confidence></issue>
</issues>`

// The import response must say what was LEFT OUT, so "1 imported" is never read as "the scan found 1".
func TestImportScan_BurpReportsSkippedInformational(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "POST", "/v1/import", "t1", importBurp)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Format != "auto" || out.Findings != 1 || out.Stored != 1 {
		t.Errorf("response = %+v, want 1 finding found and stored", out)
	}
	if out.SkippedInformational != 2 {
		t.Errorf("skipped_informational = %d, want 2", out.SkippedInformational)
	}
	if !strings.Contains(out.Detail, "2 informational items were left out") {
		t.Errorf("detail does not name what was left out: %q", out.Detail)
	}
	fs, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil || len(fs) != 1 || fs[0].Tool != "burp" {
		t.Errorf("stored findings = %+v (err %v), want the one Burp issue", fs, err)
	}
}

// An export that is ALL informational is not a clean scan and not a failed import — it is a third
// answer, and the response says which.
func TestImportScan_OnlyInformationalSaysSo(t *testing.T) {
	h := NewHandler(Deps{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Token: "platform-tok"})
	body := `<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.9">
	  <ReportItem port="22" severity="0" pluginID="10267" pluginName="SSH Server Type"/>
	</ReportHost></Report></NessusClientData_v2>`
	rec := do(h, "POST", "/v1/import?format=nessus", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out importResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Findings != 0 || out.SkippedInformational != 1 {
		t.Errorf("response = %+v, want 0 findings and 1 skipped", out)
	}
	if strings.Contains(out.Detail, "contains no findings") || !strings.Contains(out.Detail, "only informational") {
		t.Errorf("an all-informational export must not read as an empty one: %q", out.Detail)
	}
}
