package main

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector/gcpfetch"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// No trust service account → no GCP project can be connected → no fetcher, so the sync endpoint says
// live read is unavailable instead of trying to read with no identity.
func TestGCPFetcherFor_UnconfiguredIsNil(t *testing.T) {
	if gcpFetcherFor("") != nil {
		t.Fatal("a fetcher was wired with no trust service account configured")
	}
}

// Configured → each connection is read as ITS project (the account recorded at connect time), through
// an authorised client — never an unauthenticated one.
func TestGCPFetcherFor_ReadsTheConnectedProject(t *testing.T) {
	f := gcpFetcherFor("tsengine@ours.iam.gserviceaccount.com")
	if f == nil {
		t.Fatal("configured but not wired")
	}
	got, ok := f(platform.Connection{Kind: platform.ConnGCP, Account: "acme-prod"}).(*gcpfetch.Fetcher)
	if !ok || got.Project != "acme-prod" || got.Client == nil {
		t.Fatalf("fetcher not bound to the connected project with a client: %+v", got)
	}
}
