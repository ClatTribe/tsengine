package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2/google"

	"github.com/ClatTribe/tsengine/internal/connector/gcpfetch"
	"github.com/ClatTribe/tsengine/internal/platformapi"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// gcpReadScope is the narrowest scope covering every read gcpfetch makes (IAM policies, role
// definitions, service accounts, Compute, Storage, Workload Identity pools). Read-only by scope as well
// as by the role the customer granted, so a bug here cannot become a write.
const gcpReadScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

// adcDoer is an HTTP client authorised as the platform's own Application Default Credentials — the
// service account named by GCP_TRUST_SERVICE_ACCOUNT, which the customer granted read access to on
// their project. Built on first use, so a deployment without credentials fails the READ (named as a
// failed sync) rather than the boot, and a project read never silently proceeds unauthenticated.
type adcDoer struct {
	once   sync.Once
	client *http.Client
	err    error
}

func (a *adcDoer) Do(req *http.Request) (*http.Response, error) {
	a.once.Do(func() {
		a.client, a.err = google.DefaultClient(context.Background(), gcpReadScope)
	})
	if a.err != nil {
		return nil, fmt.Errorf("no Google credentials for the platform (Application Default Credentials must be the service account in GCP_TRUST_SERVICE_ACCOUNT): %w", a.err)
	}
	return a.client.Do(req)
}

// gcpFetcherFor returns the live GCP fetcher factory, or nil when no trust service account is
// configured (then /v1/cloud/sync?provider=gcp says live read is unavailable).
func gcpFetcherFor(trustSA string) platformapi.GCPFetcherFor {
	if trustSA == "" {
		return nil
	}
	doer := &adcDoer{}
	return func(c platform.Connection) platformapi.GCPFetcher {
		return &gcpfetch.Fetcher{Project: c.Account, Client: doer}
	}
}
