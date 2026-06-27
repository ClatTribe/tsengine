package platformapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/ownership"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleOwnershipChallenge issues (or returns the existing) per-asset ownership token + the DNS/file
// instructions to publish it — the proof-of-asset-ownership control (State-of-AI-in-Pentesting p35). The
// token is stored on the asset so a later /verify can check the customer actually published it.
func (d Deps) handleOwnershipChallenge(w http.ResponseWriter, r *http.Request, tenantID string) {
	asset, ok := d.findAsset(r.Context(), w, tenantID, r.PathValue("id"))
	if !ok {
		return
	}
	token := asset.Meta["ownership_token"]
	if token == "" {
		token = randomToken()
		if asset.Meta == nil {
			asset.Meta = map[string]string{}
		}
		asset.Meta["ownership_token"] = token
		if err := d.Store.PutAsset(r.Context(), *asset); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
	}
	writeJSON(w, http.StatusOK, ownership.NewChallenge(asset.Target, token))
}

// handleOwnershipVerify checks — against the LIVE target — that the asset's token is published via DNS TXT
// or the well-known file, and records the grounded result on the asset. Owner-verified ONLY when the token
// is really found (§10); the file fetch is SSRF-screened (the same guard /v1/assess uses).
func (d Deps) handleOwnershipVerify(w http.ResponseWriter, r *http.Request, tenantID string) {
	asset, ok := d.findAsset(r.Context(), w, tenantID, r.PathValue("id"))
	if !ok {
		return
	}
	token := asset.Meta["ownership_token"]
	if token == "" {
		writeJSON(w, http.StatusBadRequest, errBody("request an ownership challenge first"))
		return
	}
	ch := ownership.NewChallenge(asset.Target, token)
	res := ownership.Verify(r.Context(), ch, net.DefaultResolver, ownershipFetch)

	if asset.Meta == nil {
		asset.Meta = map[string]string{}
	}
	asset.Meta["ownership_verified"] = strconv.FormatBool(res.Verified)
	if res.Verified {
		asset.Meta["ownership_method"] = res.Method
		asset.Meta["ownership_verified_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	if err := d.Store.PutAsset(r.Context(), *asset); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("asset ownership verify", "ownership",
			map[string]any{"tenant_id": tenantID, "asset_id": asset.ID, "target": asset.Target, "verified": res.Verified, "method": res.Method},
			"asset ownership verification")
	}
	writeJSON(w, http.StatusOK, res)
}

// findAsset loads one of the tenant's assets by id, writing the 404/500 response itself and returning
// ok=false when it can't (the caller just returns). Tenant-scoped via ListAssets.
func (d Deps) findAsset(ctx context.Context, w http.ResponseWriter, tenantID, id string) (*platform.Asset, bool) {
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return nil, false
	}
	for i := range assets {
		if assets[i].ID == id {
			return &assets[i], true
		}
	}
	writeJSON(w, http.StatusNotFound, errBody("asset not found"))
	return nil, false
}

// randomToken returns a 128-bit hex token for ownership verification (unforgeable — an attacker can't guess
// another tenant's asset token to falsely claim ownership).
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ownershipFetch GETs the well-known file behind the SSRF-screened client (refuses private/loopback IPs),
// with a bounded timeout + capped read — the same hardening as the public /v1/assess probe.
func ownershipFetch(ctx context.Context, rawurl string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return "", err
	}
	resp, err := safeHTTPClient(8 * time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(b), nil
}
