package apiauthz

import "testing"

// TestEvaluate_BFLA_SoftDenialNotABypass: a privileged call that returns HTTP 200 but DENIES access in
// the body (a "soft denial" — GraphQL always returns 200; many REST APIs put authz errors in the body,
// not the status) must NOT be flagged as a BFLA bypass. The predicate keyed on status alone
// (attacker.Status/100 == 2), so every soft-denial read as a bypass — a false positive that breaks the
// verification:verified / no-FP guarantee (§10).
func TestEvaluate_BFLA_SoftDenialNotABypass(t *testing.T) {
	test := AuthzTest{Op: Operation{Method: "DELETE", URL: "/admin/users/7", Class: ClassBFLA}}
	for _, body := range []string{
		`{"error":"forbidden"}`,
		`{"message":"Unauthorized"}`,
		`{"code":"insufficient_role","detail":"admin required"}`,
		`{"error":"You do not have permission to perform this action"}`,
		`{"errors":[{"message":"Access denied"}]}`, // GraphQL-shaped 200 error
	} {
		if v := Evaluate(test, Response{200, ""}, Response{200, body}); v.Bypassed {
			t.Errorf("soft-denial 200 body falsely flagged as a BFLA bypass: %s", body)
		}
	}
	// A genuine privileged success (a real result, no denial language) is STILL flagged.
	if v := Evaluate(test, Response{200, ""}, Response{200, `{"deleted":true,"id":7}`}); !v.Bypassed || v.Class != ClassBFLA {
		t.Error("a real undenied privileged call must still be flagged BFLA")
	}
}
