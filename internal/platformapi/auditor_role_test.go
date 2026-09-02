package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The only way to give an external auditor access used to be a full member seat — which can start a
// scan, approve a fix and change settings. An auditor READS: every finding, control and report, and
// nothing that changes the workspace. The refusal is in the auth middleware, not in the buttons.
func TestAuth_AuditorIsReadOnly(t *testing.T) {
	h, _ := setup(t)
	owner := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Initech","email":"boss@initech.com","password":"ownerpass1"}`)
	var o struct{ Token string }
	_ = json.Unmarshal(owner.Body.Bytes(), &o)

	// owner is not an invitable role, and an unknown role must not fall through to member
	for _, bad := range []string{"owner", "superuser"} {
		if rec := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"x@initech.com","role":"`+bad+`"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("invite role=%s: want 400, got %d %s", bad, rec.Code, rec.Body.String())
		}
	}

	inv := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"cpa@auditfirm.com","name":"CPA","role":"auditor"}`)
	if inv.Code != http.StatusCreated {
		t.Fatalf("invite auditor: want 201, got %d %s", inv.Code, inv.Body.String())
	}
	var ir struct {
		TempPassword string                `json:"temp_password"`
		User         struct{ Role string } `json:"user"`
	}
	_ = json.Unmarshal(inv.Body.Bytes(), &ir)
	if ir.User.Role != "auditor" {
		t.Fatalf("invited user must carry the auditor role, got %s", inv.Body.String())
	}

	// sign in, rotate the temp password (auth-management is allowed — it is the auditor's own account)
	li := postJSON(h, "/v1/auth/login", "", `{"email":"cpa@auditfirm.com","password":"`+ir.TempPassword+`"}`)
	var a struct{ Token string }
	_ = json.Unmarshal(li.Body.Bytes(), &a)
	if rec := postJSON(h, "/v1/auth/password", a.Token, `{"current_password":"`+ir.TempPassword+`","new_password":"auditorpass9"}`); rec.Code != http.StatusOK {
		t.Fatalf("auditor must be able to set their own password: want 200, got %d %s", rec.Code, rec.Body.String())
	}

	// READS work: the evidence is the point of the seat
	for _, path := range []string{"/v1/assets", "/v1/findings/summary", "/v1/compliance/soc2/report", "/v1/auth/me"} {
		if rec := getBearer(h, path, a.Token); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("auditor GET %s: must be readable, got %d %s", path, rec.Code, rec.Body.String())
		}
	}

	// WRITES are refused at the gate, with a code the UI can name
	for _, path := range []string{"/v1/rescan", "/v1/assets", "/v1/killswitch", "/v1/auth/invite", "/v1/eval/model"} {
		rec := postJSON(h, path, a.Token, `{"type":"domain","target":"example.com","email":"y@initech.com"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "read_only_role") {
			// /v1/auth/invite is owner-gated first; either refusal is a refusal, but the app gate
			// must be what answers for every plain app endpoint.
			if path == "/v1/auth/invite" && rec.Code == http.StatusForbidden {
				continue
			}
			t.Errorf("auditor POST %s: want 403 read_only_role, got %d %s", path, rec.Code, rec.Body.String())
		}
	}
	// a member is unaffected by the new gate
	mi := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"dev@initech.com","role":"member"}`)
	_ = json.Unmarshal(mi.Body.Bytes(), &ir)
	ml := postJSON(h, "/v1/auth/login", "", `{"email":"dev@initech.com","password":"`+ir.TempPassword+`"}`)
	var m struct{ Token string }
	_ = json.Unmarshal(ml.Body.Bytes(), &m)
	_ = postJSON(h, "/v1/auth/password", m.Token, `{"current_password":"`+ir.TempPassword+`","new_password":"memberpass99"}`)
	if rec := postJSON(h, "/v1/assets", m.Token, `{"type":"domain","target":"example.com"}`); rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "read_only_role") {
		t.Fatalf("a member must not be treated as read-only: %d %s", rec.Code, rec.Body.String())
	}
}
