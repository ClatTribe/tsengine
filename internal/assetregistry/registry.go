// Package assetregistry resolves an asset type to its engine Handler. It lives in its
// own package (importing every per-asset handler) so multiple entrypoints —
// cmd/tsengine and cmd/platform — share one routing table without duplicating it, and
// without internal/asset importing the handlers (which would cycle).
package assetregistry

import (
	"fmt"

	"github.com/ClatTribe/tsengine/internal/asset"
	apiasset "github.com/ClatTribe/tsengine/internal/asset/api"
	cloudasset "github.com/ClatTribe/tsengine/internal/asset/cloud"
	containerasset "github.com/ClatTribe/tsengine/internal/asset/container"
	domainasset "github.com/ClatTribe/tsengine/internal/asset/domain"
	ipasset "github.com/ClatTribe/tsengine/internal/asset/ip"
	repoasset "github.com/ClatTribe/tsengine/internal/asset/repository"
	webasset "github.com/ClatTribe/tsengine/internal/asset/web"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// HandlerFor returns the Handler implementation for an asset type.
func HandlerFor(at types.AssetType) (asset.Handler, error) {
	switch at {
	case types.AssetWebApplication:
		return webasset.NewHandler(), nil
	case types.AssetAPI:
		return apiasset.NewHandler(), nil
	case types.AssetRepository:
		return repoasset.NewHandler(), nil
	case types.AssetContainerImage:
		return containerasset.NewHandler(), nil
	case types.AssetIPAddress:
		return ipasset.NewHandler(), nil
	case types.AssetDomain:
		return domainasset.NewHandler(), nil
	case types.AssetCloudAccount:
		return cloudasset.NewHandler(), nil
	default:
		return nil, fmt.Errorf("assetregistry: unhandled asset type %q", at)
	}
}
