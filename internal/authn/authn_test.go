package authn

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Error("correct password did not verify")
	}
	if VerifyPassword("wrong password here", h) {
		t.Error("wrong password verified")
	}
}

func TestHashIsSaltedAndOpaque(t *testing.T) {
	a, _ := HashPassword("samepassword1")
	b, _ := HashPassword("samepassword1")
	if a == b {
		t.Error("two hashes of the same password are identical — salt not applied")
	}
	for _, bad := range []string{"", "not$enough$parts", "bcrypt$sha256$1$x$y"} {
		if VerifyPassword("samepassword1", bad) {
			t.Errorf("malformed/foreign hash %q verified", bad)
		}
	}
}

func TestWeakPasswordRejected(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrWeakPassword {
		t.Errorf("want ErrWeakPassword for short password, got %v", err)
	}
}

func TestNewTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := NewToken()
		if err != nil || len(tok) < 32 {
			t.Fatalf("NewToken: %v (%q)", err, tok)
		}
		if seen[tok] {
			t.Fatal("NewToken returned a duplicate")
		}
		seen[tok] = true
	}
}
