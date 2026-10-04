package cloudsnap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stores(t *testing.T) map[string]Store {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Store{"mem": NewMemStore(), "file": fs}
}

const (
	awsInv = `{"provider":"aws","account_id":"111122223333","resources":[{"id":"arn:aws:s3:::cust"}]}`
	gcpInv = `{"provider":"gcp","account_id":"acme-prod","resources":[{"id":"projects/acme-prod/buckets/b"}]}`
)

// The defect this fixes: a tenant with an AWS account and a GCP project had ONE snapshot, so each ingest
// overwrote the other and the attack-path page showed only whichever cloud was posted last.
func TestTwoAccountsAreStoredSeparatelyAndBothAreRead(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(awsInv),
				CoverageGaps: map[string]string{"privilege-escalation": "no policies"}}))
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(gcpInv)}))

			a, ok, err := s.GetAccount(ctx, "t1", "aws:111122223333")
			if err != nil || !ok || !strings.Contains(string(a.Inventory), "arn:aws:s3:::cust") {
				t.Fatalf("aws account snapshot lost: ok=%v err=%v %s", ok, err, a.Inventory)
			}
			g, ok, err := s.GetAccount(ctx, "t1", "gcp:acme-prod")
			if err != nil || !ok || strings.Contains(string(g.Inventory), "arn:aws") {
				t.Fatalf("gcp account snapshot wrong: ok=%v err=%v %s", ok, err, g.Inventory)
			}

			m, ok, err := s.Get(ctx, "t1")
			if err != nil || !ok {
				t.Fatalf("merged get: ok=%v err=%v", ok, err)
			}
			var inv struct {
				Provider  string `json:"provider"`
				AccountID string `json:"account_id"`
				Resources []struct {
					ID string `json:"id"`
				} `json:"resources"`
			}
			if err := json.Unmarshal(m.Inventory, &inv); err != nil {
				t.Fatal(err)
			}
			if len(inv.Resources) != 2 {
				t.Errorf("merged view must carry BOTH clouds' resources, got %d: %s", len(inv.Resources), m.Inventory)
			}
			if inv.Provider != "multi" {
				t.Errorf("a mixed-cloud view must not claim one provider, got %q", inv.Provider)
			}
			// A coverage gap is attributed to the cloud it belongs to, not to "the tenant's cloud".
			if _, ok := m.CoverageGaps["aws:111122223333: privilege-escalation"]; !ok || len(m.CoverageGaps) != 1 {
				t.Errorf("coverage gap not attributed to its account: %v", m.CoverageGaps)
			}

			// Re-posting one account replaces only that account.
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(`{"provider":"aws","account_id":"111122223333"}`)}))
			if g2, _, _ := s.GetAccount(ctx, "t1", "gcp:acme-prod"); !strings.Contains(string(g2.Inventory), "acme-prod/buckets") {
				t.Errorf("re-posting AWS clobbered GCP: %s", g2.Inventory)
			}
			// Isolation still holds per account.
			if _, ok, _ := s.GetAccount(ctx, "t2", "aws:111122223333"); ok {
				t.Error("another tenant read t1's account")
			}
		})
	}
}

// A tenant with one account must see exactly what it stored — the merge is not allowed to reshape it.
func TestSingleAccountReadIsUnchanged(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			must(t, s.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(awsInv), CapturedAt: time.Unix(5, 0).UTC()}))
			got, ok, _ := s.Get(ctx, "t1")
			if !ok || string(got.Inventory) != awsInv || got.Account != "aws:111122223333" {
				t.Errorf("single account reshaped: %+v", got)
			}
		})
	}
}

func TestAccountOf(t *testing.T) {
	for in, want := range map[string]string{
		`{"account_id":"1"}`:                    "aws:1", // predates the provider field
		`{"provider":"GCP","account_id":" p "}`: "gcp:p",
		`{"provider":"azure"}`:                  "azure",
		``:                                      "",
		`not json`:                              "",
	} {
		if got := AccountOf(json.RawMessage(in)); got != want {
			t.Errorf("AccountOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A snapshot written before accounts were keyed lives in <tenant>.json. The first sync after the upgrade
// must diff against it (else the whole account reads as newly created), and the next write must retire it
// (else the account is merged in twice).
func TestFileStoreReadsAndRetiresTheLegacyFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(Snapshot{TenantID: "t1", Inventory: json.RawMessage(awsInv)})
	if err := os.WriteFile(filepath.Join(dir, "t1.json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	base, ok, err := fs.GetAccount(ctx, "t1", "aws:111122223333")
	if err != nil || !ok || !strings.Contains(string(base.Inventory), "arn:aws:s3:::cust") {
		t.Fatalf("legacy baseline not found: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := fs.GetAccount(ctx, "t1", "gcp:acme-prod"); ok {
		t.Error("the legacy AWS file must not answer for a different account")
	}

	// A different account leaves the legacy file in place — it still describes the AWS account.
	must(t, fs.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(gcpInv)}))
	if _, err := os.Stat(filepath.Join(dir, "t1.json")); err != nil {
		t.Fatalf("legacy file for an untouched account was removed: %v", err)
	}
	if m, _, _ := fs.Get(ctx, "t1"); !strings.Contains(string(m.Inventory), "arn:aws:s3:::cust") || !strings.Contains(string(m.Inventory), "acme-prod") {
		t.Errorf("merged view must include the legacy account: %s", m.Inventory)
	}

	// Writing the SAME account retires the legacy file, so it is not merged in twice.
	must(t, fs.Put(ctx, Snapshot{TenantID: "t1", Inventory: json.RawMessage(awsInv)}))
	if _, err := os.Stat(filepath.Join(dir, "t1.json")); !os.IsNotExist(err) {
		t.Fatalf("legacy file must be retired once its account is rewritten: %v", err)
	}
	m, _, _ := fs.Get(ctx, "t1")
	if n := strings.Count(string(m.Inventory), "arn:aws:s3:::cust"); n != 1 {
		t.Errorf("AWS resource merged %d times, want 1: %s", n, m.Inventory)
	}
}
