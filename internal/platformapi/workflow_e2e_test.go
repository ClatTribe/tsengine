package platformapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestE2E_TwoModelHITLWorkflow walks the whole practitioner workflow through the REAL handler (mux +
// auth middleware), proving the two-GTM-model story end to end:
//
//	founder signs up → declares the managed service model + names our expert as a practitioner →
//	the agent proposes a risk from a finding → our expert (an operator) sees it in their cross-tenant
//	queue → the named human decides it → the decision records the managed capacity + firm → the queue
//	clears. Plus the negative: an operator NOT on the roster sees nothing (isolation).
func TestE2E_TwoModelHITLWorkflow(t *testing.T) {
	st := store.NewMemory()
	n := 0
	d := Deps{Store: st, Recorder: ledger.NewRecorder(), Token: "op-platform-token", NewID: func() string { n++; return fmt.Sprintf("id%d", n) }}
	srv := httptest.NewServer(NewHandler(d))
	defer srv.Close()
	c := &e2eClient{t: t, base: srv.URL}

	// 1) founder self-serve signup → a tenant session
	var signup struct {
		Token  string `json:"token"`
		Tenant string `json:"tenant"`
	}
	c.do("POST", "/v1/auth/signup", nil, `{"workspace":"Acme","email":"founder@acme.com","password":"sup3rsecret"}`, http.StatusCreated, &signup)
	tenantHdr := map[string]string{"Authorization": "Bearer " + signup.Token, "X-Tenant-ID": signup.Tenant}

	// a high-severity finding exists (the engine's job; seeded directly for the test)
	if err := st.PutFinding(context.Background(), signup.Tenant, types.Finding{ID: "f1", Tool: "sqlmap", Severity: types.SeverityHigh, CWE: []string{"CWE-89"}}); err != nil {
		t.Fatal(err)
	}

	// 2) the founder declares the MANAGED model + names our delivery expert as practitioner of record
	c.do("PUT", "/v1/settings/service-model", tenantHdr, `{"service_model":"managed"}`, http.StatusOK, nil)
	c.do("POST", "/v1/practitioners", tenantHdr, `{"name":"Dana Reed","email":"dana@tensorshield.io","capacity":"managed","firm":"TensorShield Managed"}`, http.StatusOK, nil)

	// 3) the agent proposes a candidate risk from the finding (grounded)
	c.do("POST", "/v1/risks/seed", tenantHdr, ``, http.StatusOK, nil)

	// 4) our expert (an operator) is provisioned + signs in
	c.do("POST", "/v1/operator", map[string]string{"Authorization": "Bearer op-platform-token"},
		`{"email":"dana@tensorshield.io","name":"Dana Reed","firm":"TensorShield Managed","password":"op-password-1"}`, http.StatusOK, nil)
	var oplogin struct {
		Token string `json:"token"`
	}
	c.do("POST", "/v1/operator/login", nil, `{"email":"dana@tensorshield.io","password":"op-password-1"}`, http.StatusOK, &oplogin)
	opHdr := map[string]string{"Authorization": "Bearer " + oplogin.Token}

	// 5) the expert's cross-tenant queue shows the founder's pending risk (scoped to their book)
	var queue struct {
		TenantsServed int `json:"tenants_served"`
		Count         int `json:"count"`
	}
	c.do("GET", "/v1/operator/queue", opHdr, ``, http.StatusOK, &queue)
	if queue.TenantsServed != 1 || queue.Count < 1 {
		t.Fatalf("expected the operator to see 1 tenant with >=1 pending item, got served=%d count=%d", queue.TenantsServed, queue.Count)
	}

	// 6) the named human decides the risk (in the client workspace) → records the managed capacity
	var decided platform.Risk
	c.do("POST", "/v1/risks/risk-injection/decision", tenantHdr, `{"treatment":"mitigate","owner":"Dana Reed","rationale":"WAF + parameterized queries"}`, http.StatusOK, &decided)
	if decided.Capacity != platform.CapacityManaged || decided.Firm != "TensorShield Managed" {
		t.Fatalf("the decision must record the managed capacity + firm, got %q/%q", decided.Capacity, decided.Firm)
	}

	// 7) the queue clears (the item was handled)
	var queue2 struct {
		Count int `json:"count"`
	}
	c.do("GET", "/v1/operator/queue", opHdr, ``, http.StatusOK, &queue2)
	if queue2.Count != 0 {
		t.Errorf("after the decision the queue should be empty, got %d", queue2.Count)
	}

	// 8) isolation: a DIFFERENT operator (not on the roster) sees nothing
	c.do("POST", "/v1/operator", map[string]string{"Authorization": "Bearer op-platform-token"},
		`{"email":"other@msp.com","password":"op-password-2"}`, http.StatusOK, nil)
	var other struct {
		Token string `json:"token"`
	}
	c.do("POST", "/v1/operator/login", nil, `{"email":"other@msp.com","password":"op-password-2"}`, http.StatusOK, &other)
	var otherQ struct {
		TenantsServed int `json:"tenants_served"`
	}
	c.do("GET", "/v1/operator/queue", map[string]string{"Authorization": "Bearer " + other.Token}, ``, http.StatusOK, &otherQ)
	if otherQ.TenantsServed != 0 {
		t.Errorf("ISOLATION: an unassigned operator must serve 0 tenants, got %d", otherQ.TenantsServed)
	}
}

type e2eClient struct {
	t    *testing.T
	base string
}

func (c *e2eClient) do(method, path string, headers map[string]string, body string, wantCode int, out any) {
	c.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(res.Body)
	if res.StatusCode != wantCode {
		c.t.Fatalf("%s %s: want %d, got %d: %s", method, path, wantCode, res.StatusCode, string(rb))
	}
	if out != nil {
		if err := json.Unmarshal(rb, out); err != nil {
			c.t.Fatalf("%s %s: decode: %v (%s)", method, path, err, string(rb))
		}
	}
}
