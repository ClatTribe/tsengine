package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func contactDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	return Deps{Store: st, NewID: func() string { n++; return fmt.Sprintf("c%d", n) }}
}

func addContact(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/contacts", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handleAddContact(rec, req, "ten-1")
	return rec
}

func TestContacts_AddListOrderedDelete(t *testing.T) {
	d := contactDeps(t)
	// add out of order; list must come back by escalation order
	if rec := addContact(d, `{"name":"Bob","role":"Backup","phone":"+15550002","order":2}`); rec.Code != http.StatusOK {
		t.Fatalf("add Bob: %d %s", rec.Code, rec.Body.String())
	}
	rec := addContact(d, `{"name":"Alice","role":"Primary","email":"alice@acme.com","phone":"+15550001","order":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add Alice: %d %s", rec.Code, rec.Body.String())
	}
	var alice platform.Contact
	_ = json.Unmarshal(rec.Body.Bytes(), &alice)

	lreq := httptest.NewRequest(http.MethodGet, "/v1/contacts", nil)
	lrec := httptest.NewRecorder()
	d.handleListContacts(lrec, lreq, "ten-1")
	var list []platform.Contact
	_ = json.Unmarshal(lrec.Body.Bytes(), &list)
	if len(list) != 2 || list[0].Name != "Alice" || list[1].Name != "Bob" {
		t.Fatalf("roster should be ordered Alice(1), Bob(2), got %+v", list)
	}

	dreq := httptest.NewRequest(http.MethodDelete, "/v1/contacts/"+alice.ID, nil)
	dreq.SetPathValue("id", alice.ID)
	drec := httptest.NewRecorder()
	d.handleDeleteContact(drec, dreq, "ten-1")
	if drec.Code != http.StatusOK {
		t.Fatalf("delete: %d", drec.Code)
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if len(tn.Contacts) != 1 || tn.Contacts[0].Name != "Bob" {
		t.Errorf("after delete only Bob remains, got %+v", tn.Contacts)
	}
}

func TestContacts_Validation(t *testing.T) {
	d := contactDeps(t)
	cases := map[string]string{
		"no name":           `{"name":"","phone":"+15550001"}`,
		"no email or phone": `{"name":"Nobody"}`,
		"bad email":         `{"name":"X","email":"notanemail"}`,
	}
	for name, body := range cases {
		if rec := addContact(d, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	// unknown delete → 404
	dreq := httptest.NewRequest(http.MethodDelete, "/v1/contacts/nope", nil)
	dreq.SetPathValue("id", "nope")
	drec := httptest.NewRecorder()
	d.handleDeleteContact(drec, dreq, "ten-1")
	if drec.Code != http.StatusNotFound {
		t.Errorf("unknown delete want 404, got %d", drec.Code)
	}
}
