// Package azremediate is the LIVE Azure write path for cloud remediation — the SDK-backed
// implementation of connector.AzureWriter that connector.Azure.Apply routes to (it returns an
// honest "no live write path" stub when no writer is wired). It is a SEPARATE package so the Azure
// SDK stays out of the core connector package, mirroring awsremediate / gcpremediate.
//
// Today it implements the Azure analogue of S3 Block Public Access: disabling
// AllowBlobPublicAccess on a storage account (no blob/container can be made anonymously public).
// Reached ONLY after the HITL gate (§18.2 inv. 3). The platform's service principal
// (DefaultAzureCredential) must hold a scoped write role (e.g. Storage Account Contributor) on the
// target subscription — the deployment step.
package azremediate

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// storageAccountAPI is the minimal ARM-storage surface the writer uses — a test injects a fake
// (no Azure creds).
type storageAccountAPI interface {
	// DisablePublicAccess sets AllowBlobPublicAccess=false on the account.
	DisablePublicAccess(ctx context.Context, resourceGroup, account string) error
}

// StorageWriter implements connector.AzureWriter over the real azure-sdk-for-go ARM-storage SDK.
type StorageWriter struct {
	// newClient builds the per-subscription accounts client. Set by NewStorageWriter to the real
	// SDK path; a test overrides it.
	newClient func(ctx context.Context, subscriptionID string) (storageAccountAPI, error)
}

// NewStorageWriter builds the live writer. It uses DefaultAzureCredential (env / managed identity /
// Azure CLI) — the platform's service principal must hold a scoped storage-write role on the target
// subscription.
func NewStorageWriter() *StorageWriter {
	w := &StorageWriter{}
	w.newClient = w.realClient
	return w
}

// DisableStoragePublicAccess sets AllowBlobPublicAccess=false on the storage account — reversible,
// idempotent — the fix for a publicly-exposed Azure storage account.
func (w *StorageWriter) DisableStoragePublicAccess(ctx context.Context, subscriptionID, resourceGroup, account string) error {
	if subscriptionID == "" || resourceGroup == "" || account == "" {
		return fmt.Errorf("azremediate: subscription, resource group, and account are all required")
	}
	client, err := w.newClient(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("azremediate: build storage client: %w", err)
	}
	if err := client.DisablePublicAccess(ctx, resourceGroup, account); err != nil {
		return fmt.Errorf("azremediate: disable public access(%s/%s): %w", resourceGroup, account, err)
	}
	return nil
}

// realClient builds the live ARM-storage accounts client for the subscription. The only code
// touching credentials/network — replaced by a fake in tests.
func (w *StorageWriter) realClient(_ context.Context, subscriptionID string) (storageAccountAPI, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	c, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return &realStorage{c: c}, nil
}

type realStorage struct{ c *armstorage.AccountsClient }

func (r *realStorage) DisablePublicAccess(ctx context.Context, resourceGroup, account string) error {
	_, err := r.c.Update(ctx, resourceGroup, account, armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{
			AllowBlobPublicAccess: to.Ptr(false),
		},
	}, nil)
	return err
}
