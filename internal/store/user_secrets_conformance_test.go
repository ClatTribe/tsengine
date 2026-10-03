package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A password-reset token must SURVIVE the store. User's secret fields are json:"-" so a handler can
// never leak them, and that tag made every JSON-backed store drop them on save: /v1/auth/forgot set the
// token, the next read returned it empty, and every reset link on a persistent deployment was refused.
// The memory store kept the struct, so nothing else in the suite could see it. This runs every store,
// and the file store is REOPENED so the snapshot path is exercised, not just the in-process copy.
func TestConformance_UserSecretsSurviveTheStore(t *testing.T) {
	exp := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			ctx := context.Background()
			s := f.open(t)
			u := platform.User{ID: "usr-1", TenantID: "t1", Email: "ada@acme.example", Role: platform.RoleOwner,
				PasswordHash: "h", ResetTokenHash: "deadbeef", ResetTokenExpires: exp}
			orFail(t, s.PutUser(ctx, u))

			check := func(where string, got platform.User) {
				t.Helper()
				if got.ResetTokenHash != "deadbeef" || !got.ResetTokenExpires.Equal(exp) {
					t.Errorf("%s: reset token lost on save (hash=%q expires=%v) — every reset link would be refused",
						where, got.ResetTokenHash, got.ResetTokenExpires)
				}
			}
			got, err := s.GetUser(ctx, "usr-1")
			orFail(t, err)
			check("GetUser", got)
			got, err = s.GetUserByEmail(ctx, "ADA@acme.example")
			orFail(t, err)
			check("GetUserByEmail", got)
			list, err := s.ListUsers(ctx, "t1")
			orFail(t, err)
			if len(list) != 1 {
				t.Fatalf("ListUsers = %d users, want 1", len(list))
			}
			check("ListUsers", list[0])

			// Clearing it must persist too, or a used token would stay valid forever.
			u.ResetTokenHash, u.ResetTokenExpires = "", time.Time{}
			orFail(t, s.PutUser(ctx, u))
			got, _ = s.GetUser(ctx, "usr-1")
			if got.ResetTokenHash != "" {
				t.Errorf("a cleared reset token came back as %q — a used link would stay valid", got.ResetTokenHash)
			}
		})
	}
}

// The file store's durability is the snapshot on disk; reopen it and read the token back.
func TestFileStore_UserSecretsSurviveReopen(t *testing.T) {
	path := t.TempDir() + "/store.json"
	s, err := OpenFile(path)
	orFail(t, err)
	orFail(t, s.PutUser(context.Background(), platform.User{ID: "u", TenantID: "t", Email: "a@b.c", ResetTokenHash: "cafe"}))
	re, err := OpenFile(path)
	orFail(t, err)
	got, err := re.GetUser(context.Background(), "u")
	orFail(t, err)
	if got.ResetTokenHash != "cafe" {
		t.Errorf("reset token after reopen = %q, want it to survive the snapshot", got.ResetTokenHash)
	}
}

// The other half of the bargain: the shape a HANDLER serializes must still carry no secret. If someone
// "fixes" persistence by dropping the json:"-" tag, this fails.
func TestUserJSONNeverCarriesSecrets(t *testing.T) {
	b, err := json.Marshal(platform.User{ID: "u", ResetTokenHash: "deadbeef", ResetTokenExpires: time.Now()})
	orFail(t, err)
	if strings.Contains(string(b), "deadbeef") || strings.Contains(string(b), "reset_token") {
		t.Errorf("platform.User serializes a secret to clients: %s", b)
	}
}
