package azremediate

import (
	"context"
	"errors"
	"testing"
)

type fakeStorage struct {
	rg, account string
	err         error
}

func (f *fakeStorage) DisablePublicAccess(_ context.Context, resourceGroup, account string) error {
	f.rg, f.account = resourceGroup, account
	return f.err
}

func TestStorageWriter_DisablesPublicAccess(t *testing.T) {
	fake := &fakeStorage{}
	w := NewStorageWriter()
	w.newClient = func(context.Context, string) (storageAccountAPI, error) { return fake, nil }

	if err := w.DisableStoragePublicAccess(context.Background(), "sub-1", "rg-prod", "acmestorage"); err != nil {
		t.Fatalf("DisableStoragePublicAccess: %v", err)
	}
	if fake.rg != "rg-prod" || fake.account != "acmestorage" {
		t.Errorf("writer called with rg=%q account=%q", fake.rg, fake.account)
	}
}

func TestStorageWriter_RequiresAllParts(t *testing.T) {
	w := NewStorageWriter()
	w.newClient = func(context.Context, string) (storageAccountAPI, error) { return &fakeStorage{}, nil }
	for _, c := range []struct{ sub, rg, acct string }{
		{"", "rg", "a"}, {"sub", "", "a"}, {"sub", "rg", ""},
	} {
		if err := w.DisableStoragePublicAccess(context.Background(), c.sub, c.rg, c.acct); err == nil {
			t.Errorf("missing part (%q/%q/%q) must error", c.sub, c.rg, c.acct)
		}
	}
}

func TestStorageWriter_SurfacesAPIError(t *testing.T) {
	w := NewStorageWriter()
	w.newClient = func(context.Context, string) (storageAccountAPI, error) {
		return &fakeStorage{err: errors.New("AuthorizationFailed")}, nil
	}
	if err := w.DisableStoragePublicAccess(context.Background(), "s", "r", "a"); err == nil {
		t.Fatal("API error must surface")
	}
}

func TestNewStorageWriter_WiresRealClientFactory(t *testing.T) {
	if NewStorageWriter().newClient == nil {
		t.Fatal("newClient factory not wired")
	}
}
