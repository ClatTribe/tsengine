package connector

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
)

const escPolicy = `{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicyVersion"],"Resource":"*"}]}`

// THE FAILURE THIS EXISTS FOR: principals present, policies absent. Escalation is computed
// from the documents, so the result is exactly zero escalation edges — indistinguishable
// from an account where nobody can escalate.
func TestCoverAWS_PrincipalsWithoutPoliciesIsDeclared(t *testing.T) {
	c := CoverAWS(awsinventory.RawAWS{
		AccountID: "1",
		Roles:     []awsinventory.RawIAMRole{{ARN: "arn:aws:iam::1:role/app", Name: "app", Admin: false}},
	})
	if c.Complete() {
		t.Fatal("no policy documents means no escalation can be computed — that must be declared")
	}
	note := c.Notes["privilege-escalation"]
	if !strings.Contains(note, "policies") {
		t.Fatalf("the note must name the FIELD to populate, or a caller cannot act on it: %q", note)
	}
	if !strings.Contains(note, "BECOME") {
		t.Fatalf("the note must distinguish who IS admin from who can BECOME one: %q", note)
	}
	if !strings.Contains(c.Summary(), "UNREAD, not safe") {
		t.Fatalf("the summary must say an empty result is unread rather than clean: %q", c.Summary())
	}
}

func TestCoverAWS_PoliciesPresentIsComplete(t *testing.T) {
	c := CoverAWS(awsinventory.RawAWS{
		AccountID: "1",
		Roles: []awsinventory.RawIAMRole{{
			ARN: "arn:aws:iam::1:role/app", PoliciesJSON: []string{escPolicy},
		}},
	})
	if !c.Complete() {
		t.Fatalf("a snapshot carrying policy documents can answer the question: %+v", c.Notes)
	}
	if strings.Contains(c.Summary(), "NOT evaluated") {
		t.Fatalf("a complete snapshot must not carry a warning — a permanent warning is ignored: %q", c.Summary())
	}
}

func TestCoverAWS_NoPrincipalsAtAllIsItsOwnGap(t *testing.T) {
	c := CoverAWS(awsinventory.RawAWS{AccountID: "1"})
	if _, ok := c.Notes["identity"]; !ok {
		t.Fatal("an inventory with no principals cannot start an attack path from one")
	}
}

func TestCoverGCP_MissingBindingsIsDeclared(t *testing.T) {
	c := CoverGCP(gcpinventory.RawGCP{
		ProjectID:       "p",
		ServiceAccounts: []gcpinventory.RawGCPSA{{Email: "sa@p.iam.gserviceaccount.com"}},
	})
	if c.Complete() {
		t.Fatal("no bindings means no escalation can be computed")
	}
	if !strings.Contains(c.Notes["privilege-escalation"], "bindings") {
		t.Fatalf("name the field: %q", c.Notes["privilege-escalation"])
	}
}

// GCP's extra failure mode: an unresolvable custom role causes SILENT under-reporting,
// because derivePrivesc refuses to build an edge on a role it cannot resolve. Naming those
// roles is the only way a caller learns the answer was partial.
func TestCoverGCP_UnresolvableRolesAreNamed(t *testing.T) {
	c := CoverGCP(gcpinventory.RawGCP{
		ProjectID: "p",
		Members:   []gcpinventory.RawGCPMember{{Member: "user:a@acme.com"}},
		Bindings: []gcpinventory.RawGCPBinding{
			{Role: "roles/custom.mystery", Members: []string{"user:a@acme.com"}},
			{Role: "roles/viewer", Members: []string{"user:a@acme.com"}},
		},
	})
	note := c.Notes["custom-role-permissions"]
	if !strings.Contains(note, "roles/custom.mystery") {
		t.Fatalf("the unresolvable role must be named: %q", note)
	}
	if strings.Contains(note, "roles/viewer") {
		t.Fatalf("a basic role gcpiam understands inline is not a gap: %q", note)
	}
	if !strings.Contains(note, "role_defs") {
		t.Fatalf("name the field to populate: %q", note)
	}
}

func TestCoverGCP_ResolvableBindingsAreComplete(t *testing.T) {
	c := CoverGCP(gcpinventory.RawGCP{
		ProjectID: "p",
		Members:   []gcpinventory.RawGCPMember{{Member: "user:a@acme.com"}},
		Bindings:  []gcpinventory.RawGCPBinding{{Role: "roles/custom.x", Members: []string{"user:a@acme.com"}}},
		RoleDefs:  map[string][]string{"roles/custom.x": {"storage.objects.get"}},
	})
	if !c.Complete() {
		t.Fatalf("every role resolved and bindings present — nothing is unanswerable: %+v", c.Notes)
	}
}

// A long list must not flood the response; the count still has to be honest.
func TestCoverGCP_ManyUnknownRolesAreTruncatedWithACount(t *testing.T) {
	raw := gcpinventory.RawGCP{ProjectID: "p", Members: []gcpinventory.RawGCPMember{{Member: "user:a@acme.com"}}}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		raw.Bindings = append(raw.Bindings, gcpinventory.RawGCPBinding{
			Role: "roles/custom." + n, Members: []string{"user:a@acme.com"}})
	}
	note := CoverGCP(raw).Notes["custom-role-permissions"]
	if !strings.Contains(note, "and 2 more") {
		t.Fatalf("a truncated list must say how many it dropped: %q", note)
	}
}
