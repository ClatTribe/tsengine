package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/internal/platformapi"
)

func TestReadDomainList_SkipsBlanksAndComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "domains.txt")
	_ = os.WriteFile(p, []byte("# prospects\nacme.com\n\n  beta.io  \n#skip.me\n"), 0o600)
	got, err := readDomainList(p)
	if err != nil || len(got) != 2 || got[0] != "acme.com" || got[1] != "beta.io" {
		t.Fatalf("want [acme.com beta.io], got %v err=%v", got, err)
	}
}

// A non-public input must be refused without any network I/O — the batch runner reports it per
// domain and moves on, never scoring it.
func TestAssessDomain_RefusesNonPublicInputOffline(t *testing.T) {
	for _, bad := range []string{"localhost", "metadata.google.internal", "10.0.0.1", "not a domain"} {
		if _, err := platformapi.AssessDomain(context.Background(), bad); !errors.Is(err, platformapi.ErrAssessDomain) {
			t.Errorf("%q: want ErrAssessDomain, got %v", bad, err)
		}
	}
}
