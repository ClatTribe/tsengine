package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 column: the secret is the ASCII "12345678901234567890" and the vectors
// are 8 digits. Checked through hotp() at 8 digits so the implementation is pinned to the standard,
// not to our own expectations.
func TestHOTP_RFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		if got := hotp(key, uint64(v.unix/Period), 8); got != v.want {
			t.Errorf("t=%d: got %s, want %s (RFC 6238 Appendix B)", v.unix, got, v.want)
		}
	}
}

func secretFor(t *testing.T) string {
	t.Helper()
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
}

func TestVerify_AcceptsAdjacentStepsOnly(t *testing.T) {
	sec := secretFor(t)
	now := time.Unix(1234567890, 0)
	for _, d := range []int64{-1, 0, 1} {
		at := now.Add(time.Duration(d*Period) * time.Second)
		c, _ := Code(sec, at)
		step, ok := Verify(sec, c, now)
		if !ok || step != Step(at) {
			t.Errorf("drift %+d step: ok=%v step=%d want %d", d, ok, step, Step(at))
		}
	}
	for _, d := range []int64{-2, 2} {
		c, _ := Code(sec, now.Add(time.Duration(d*Period)*time.Second))
		if _, ok := Verify(sec, c, now); ok {
			t.Errorf("a code %d steps away was accepted — the window is wider than one step either side", d)
		}
	}
}

func TestVerify_RefusesMalformedInput(t *testing.T) {
	sec := secretFor(t)
	now := time.Unix(1234567890, 0)
	c, _ := Code(sec, now)
	for _, bad := range []string{"", "12345", c + "0", "abcdef"} {
		if _, ok := Verify(sec, bad, now); ok {
			t.Errorf("Verify accepted %q", bad)
		}
	}
	if _, ok := Verify("", c, now); ok {
		t.Error("an empty secret verified a code")
	}
	// People type codes with a space in the middle; that must still work.
	if _, ok := Verify(sec, c[:3]+" "+c[3:], now); !ok {
		t.Error("a code typed with a space was refused")
	}
	// A lower-case or spaced secret (as typed from an app's manual-entry screen) decodes the same.
	if _, ok := Verify(strings.ToLower(sec[:8])+" "+sec[8:], c, now); !ok {
		t.Error("a lower-case, spaced secret was not accepted")
	}
}

func TestNewSecret_IsRandomAndDecodes(t *testing.T) {
	a, _ := NewSecret()
	b, _ := NewSecret()
	if a == b || len(a) != 32 {
		t.Errorf("secrets %q / %q: want two distinct 160-bit (32-char) secrets", a, b)
	}
	if _, err := Code(a, time.Now()); err != nil {
		t.Errorf("a fresh secret does not decode: %v", err)
	}
}

func TestURI_IsWhatAuthenticatorsImport(t *testing.T) {
	u := URI("TensorShield", "ada@acme.example", "JBSWY3DPEHPK3PXP")
	for _, want := range []string{"otpauth://totp/TensorShield:ada@acme.example?", "secret=JBSWY3DPEHPK3PXP", "issuer=TensorShield", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI %q missing %q", u, want)
		}
	}
}

func TestRecoveryCodes_SingleUseAndNormalised(t *testing.T) {
	plain, hashes, err := NewRecoveryCodes()
	if err != nil || len(plain) != RecoveryCount || len(hashes) != RecoveryCount {
		t.Fatalf("got %d/%d codes, err %v", len(plain), len(hashes), err)
	}
	for _, h := range hashes {
		for _, p := range plain {
			if h == p {
				t.Fatal("a recovery code is stored in plain text")
			}
		}
	}
	// Typed in upper case without the dash, it still matches — and only once.
	typed := strings.ToUpper(strings.ReplaceAll(plain[3], "-", ""))
	rest, ok := ConsumeRecovery(hashes, typed)
	if !ok || len(rest) != RecoveryCount-1 {
		t.Fatalf("first use: ok=%v remaining=%d", ok, len(rest))
	}
	if _, ok := ConsumeRecovery(rest, plain[3]); ok {
		t.Error("a recovery code worked twice")
	}
	if _, ok := ConsumeRecovery(rest, "nope0-nope0"); ok {
		t.Error("an unknown recovery code was accepted")
	}
}
