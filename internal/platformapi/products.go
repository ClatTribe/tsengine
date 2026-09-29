package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/productscope"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// products.go is CTEM scoping (ADR 0028 G2) in the buyer's terms: which assets make up each product the
// tenant's customers buy and review.
//
// The platform PROPOSES from links it can prove (internal/productscope) and a NAMED HUMAN confirms.
// Only confirmed products are stored; proposals are recomputed on every read so they cannot go stale.
// A confirmed product then becomes the scope of the deliverable that matters most to this ICP — the
// VAPT report (GET /v1/vapt/report?product=<id>) says which product it covers and who agreed to that.

// linksNote is rendered verbatim beside every proposal so a reader knows what a grouping does and does
// NOT rest on.
const linksNote = "Assets are grouped only by links we can prove: web and API assets under the same " +
	"registered domain, and a GitHub repository whose workflows can assume a role in a connected cloud " +
	"account. We never group by similar names, by who has access, or by a leaked key. Anything no such " +
	"link reaches is left for you to place."

type productAsset struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Target string `json:"target"`
	// Shared marks an asset that belongs to more than one confirmed product (shared infrastructure).
	Shared bool `json:"shared,omitempty"`
}

type productExposure struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

type productSuggestionView struct {
	Asset productAsset          `json:"asset"`
	Kind  productscope.LinkKind `json:"kind"`
	Why   string                `json:"why"`
}

type productView struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Owner       string         `json:"owner,omitempty"`
	ConfirmedBy string         `json:"confirmed_by"`
	ConfirmedAt time.Time      `json:"confirmed_at"`
	Assets      []productAsset `json:"assets"`
	// MissingAssetIDs are members that no longer exist (the asset was removed). Reported rather than
	// silently dropped: a confirmed scope that quietly shrank is not what the human confirmed.
	MissingAssetIDs []string                `json:"missing_asset_ids,omitempty"`
	Exposure        productExposure         `json:"exposure"`
	Suggestions     []productSuggestionView `json:"suggestions"`
}

type proposalView struct {
	Name   string              `json:"name"`
	Assets []productAsset      `json:"assets"`
	Links  []productscope.Link `json:"links"`
}

type unassignedView struct {
	Assets []productAsset      `json:"assets"`
	Links  []productscope.Link `json:"links"`
}

type outOfScopeView struct {
	Asset  productAsset `json:"asset"`
	By     string       `json:"by"`
	Reason string       `json:"reason,omitempty"`
	At     time.Time    `json:"at"`
}

type productsResponse struct {
	Products   []productView    `json:"products"`
	Proposals  []proposalView   `json:"proposals"`
	Unassigned []unassignedView `json:"unassigned"`
	OutOfScope []outOfScopeView `json:"out_of_scope"`
	LinksNote  string           `json:"links_note"`
	// DeployLinksUnavailable is set when the estate graph could not be composed, so repo→account
	// deploy links are absent for a reason other than there being none.
	DeployLinksUnavailable bool `json:"deploy_links_unavailable,omitempty"`
}

func (d Deps) handleListProducts(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var g *estategraph.Graph
	unavailable := false
	if eg, gerr := d.composeEstate(ctx, tenantID); gerr == nil {
		g = eg
	} else {
		unavailable = true
	}
	links := productscope.Links(assets, g)
	res := productscope.Propose(assets, links, t.Products, t.OutOfScope)

	byID := make(map[string]platform.Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}
	memberships := map[string]int{}
	for _, p := range t.Products {
		for _, id := range p.AssetIDs {
			memberships[id]++
		}
	}
	view := func(id string) productAsset {
		a := byID[id]
		return productAsset{ID: a.ID, Type: a.Type, Target: a.Target, Shared: memberships[id] > 1}
	}

	exposure, err := d.productExposure(ctx, tenantID, assets, t.Products)
	if err != nil {
		respond(w, nil, err)
		return
	}

	out := productsResponse{Products: []productView{}, Proposals: []proposalView{}, Unassigned: []unassignedView{},
		OutOfScope: []outOfScopeView{}, LinksNote: linksNote, DeployLinksUnavailable: unavailable}

	for _, p := range t.Products {
		pv := productView{ID: p.ID, Name: p.Name, Owner: p.Owner, ConfirmedBy: p.ConfirmedBy, ConfirmedAt: p.ConfirmedAt,
			Assets: []productAsset{}, Suggestions: []productSuggestionView{}, Exposure: exposure[p.ID]}
		for _, id := range p.AssetIDs {
			if _, ok := byID[id]; ok {
				pv.Assets = append(pv.Assets, view(id))
			} else {
				pv.MissingAssetIDs = append(pv.MissingAssetIDs, id)
			}
		}
		for _, s := range res.Suggestions {
			if s.ProductID == p.ID {
				pv.Suggestions = append(pv.Suggestions, productSuggestionView{Asset: view(s.AssetID), Kind: s.Link.Kind, Why: s.Link.Why})
			}
		}
		out.Products = append(out.Products, pv)
	}
	for _, pr := range res.Proposals {
		v := proposalView{Name: pr.Name, Links: pr.Links, Assets: []productAsset{}}
		for _, id := range pr.AssetIDs {
			v.Assets = append(v.Assets, view(id))
		}
		out.Proposals = append(out.Proposals, v)
	}
	for _, grp := range res.Unassigned {
		v := unassignedView{Links: grp.Links, Assets: []productAsset{}}
		for _, id := range grp.AssetIDs {
			v.Assets = append(v.Assets, view(id))
		}
		out.Unassigned = append(out.Unassigned, v)
	}
	ids := make([]string, 0, len(t.OutOfScope))
	for id := range t.OutOfScope {
		if _, ok := byID[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		ex := t.OutOfScope[id]
		out.OutOfScope = append(out.OutOfScope, outOfScopeView{Asset: view(id), By: ex.By, Reason: ex.Reason, At: ex.At})
	}
	writeJSON(w, http.StatusOK, out)
}

// productExposure counts each product's distinct open issues by worst severity — the same identity
// (crossdetect.DedupKey) and suppression (ignore rules) the issues view uses, so the number here and
// the number on /issues can never disagree about the same finding.
func (d Deps) productExposure(ctx context.Context, tenantID string, assets []platform.Asset, products []platform.Product) (map[string]productExposure, error) {
	out := make(map[string]productExposure, len(products))
	if len(products) == 0 {
		return out, nil
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	ignored := map[string]bool{}
	if rules, rerr := d.Store.ListIgnoreRules(ctx, tenantID); rerr == nil {
		for _, rl := range rules {
			ignored[rl.IssueKey] = true
		}
	}
	// asset id → worst severity per issue key
	perAsset := map[string]map[string]types.Severity{}
	for _, f := range findings {
		id := grc.AssetForFinding(f, assets)
		k := crossdetect.DedupKey(f)
		if id == "" || k == "" || ignored[k] {
			continue
		}
		if perAsset[id] == nil {
			perAsset[id] = map[string]types.Severity{}
		}
		if cur, ok := perAsset[id][k]; !ok || sevWeight(f.Severity) > sevWeight(cur) {
			perAsset[id][k] = f.Severity
		}
	}
	for _, p := range products {
		worst := map[string]types.Severity{}
		for _, id := range p.AssetIDs {
			for k, s := range perAsset[id] {
				if cur, ok := worst[k]; !ok || sevWeight(s) > sevWeight(cur) {
					worst[k] = s
				}
			}
		}
		var e productExposure
		for _, s := range worst {
			e.Total++
			switch s {
			case types.SeverityCritical:
				e.Critical++
			case types.SeverityHigh:
				e.High++
			case types.SeverityMedium:
				e.Medium++
			case types.SeverityLow:
				e.Low++
			default:
				e.Info++
			}
		}
		out[p.ID] = e
	}
	return out, nil
}

func sevWeight(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	}
	return 0
}

type productBody struct {
	Name        string   `json:"name"`
	Owner       string   `json:"owner"`
	AssetIDs    []string `json:"asset_ids"`
	ConfirmedBy string   `json:"confirmed_by"`
}

// validateMembers checks every id names one of THIS tenant's assets and none is out of scope. Ids are
// validated, never trusted: an id for an asset this tenant does not have is not a member, and honouring
// it would cross the isolation boundary the store enforces (§18.2 inv. 2).
func validateMembers(ids []string, assets []platform.Asset, out map[string]platform.ScopeExclusion) ([]string, string) {
	known := make(map[string]bool, len(assets))
	for _, a := range assets {
		known[a.ID] = true
	}
	seen := map[string]bool{}
	var clean, unknown, excluded []string
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		switch {
		case !known[id]:
			unknown = append(unknown, id)
		case isExcluded(out, id):
			excluded = append(excluded, id)
		default:
			clean = append(clean, id)
		}
	}
	switch {
	case len(unknown) > 0:
		return nil, "unknown asset ids: " + strings.Join(unknown, ", ")
	case len(excluded) > 0:
		return nil, "these assets are marked out of scope — bring them back into scope first: " + strings.Join(excluded, ", ")
	case len(clean) == 0:
		return nil, "a product needs at least one asset"
	}
	sort.Strings(clean)
	return clean, ""
}

func (d Deps) handleCreateProduct(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body productBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name, by := strings.TrimSpace(body.Name), strings.TrimSpace(body.ConfirmedBy)
	if name == "" || len(name) > 120 {
		writeJSON(w, http.StatusBadRequest, errBody("name is required (at most 120 characters)"))
		return
	}
	if by == "" {
		// The scope of a report a customer's reviewer reads cannot be agreed to by nobody.
		writeJSON(w, http.StatusBadRequest, errBody("confirmed_by is required: a named person must confirm what a product consists of"))
		return
	}
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	for _, p := range t.Products {
		if strings.EqualFold(p.Name, name) {
			writeJSON(w, http.StatusBadRequest, errBody("a product with that name already exists"))
			return
		}
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	ids, msg := validateMembers(body.AssetIDs, assets, t.OutOfScope)
	if msg != "" {
		writeJSON(w, http.StatusBadRequest, errBody(msg))
		return
	}
	now := time.Now().UTC()
	id := "prod-" + tenantID
	if d.NewID != nil {
		id = "prod-" + d.NewID()
	}
	p := platform.Product{ID: id, Name: name, Owner: strings.TrimSpace(body.Owner), AssetIDs: ids,
		ConfirmedBy: by, ConfirmedAt: now, CreatedAt: now}
	t.Products = append(t.Products, p)
	if err := d.Store.PutTenant(ctx, t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("product scope confirmed", "product_scope",
			map[string]any{"tenant_id": tenantID, "product_id": p.ID, "name": p.Name, "asset_ids": p.AssetIDs, "confirmed_by": by},
			"named human confirmed the assets that make up a product")
	}
	writeJSON(w, http.StatusOK, p)
}

func (d Deps) handleUpdateProduct(w http.ResponseWriter, r *http.Request, tenantID string) {
	pid := r.PathValue("id")
	var body struct {
		Name        *string  `json:"name"`
		Owner       *string  `json:"owner"`
		AssetIDs    []string `json:"asset_ids"`
		ConfirmedBy string   `json:"confirmed_by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	by := strings.TrimSpace(body.ConfirmedBy)
	if by == "" {
		// Every change re-confirms: a scope edited by one person and "confirmed" by another is not a
		// confirmation of what it now contains.
		writeJSON(w, http.StatusBadRequest, errBody("confirmed_by is required: a named person must confirm the changed scope"))
		return
	}
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	idx := -1
	for i, p := range t.Products {
		if p.ID == pid {
			idx = i
		}
	}
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, errBody("product not found"))
		return
	}
	p := t.Products[idx]
	if body.Name != nil {
		n := strings.TrimSpace(*body.Name)
		if n == "" || len(n) > 120 {
			writeJSON(w, http.StatusBadRequest, errBody("name is required (at most 120 characters)"))
			return
		}
		for i, o := range t.Products {
			if i != idx && strings.EqualFold(o.Name, n) {
				writeJSON(w, http.StatusBadRequest, errBody("a product with that name already exists"))
				return
			}
		}
		p.Name = n
	}
	if body.Owner != nil {
		p.Owner = strings.TrimSpace(*body.Owner)
	}
	if body.AssetIDs != nil {
		assets, err := d.Store.ListAssets(ctx, tenantID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		ids, msg := validateMembers(body.AssetIDs, assets, t.OutOfScope)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, errBody(msg))
			return
		}
		p.AssetIDs = ids
	}
	p.ConfirmedBy, p.ConfirmedAt = by, time.Now().UTC()
	t.Products[idx] = p
	if err := d.Store.PutTenant(ctx, t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("product scope changed", "product_scope",
			map[string]any{"tenant_id": tenantID, "product_id": p.ID, "name": p.Name, "asset_ids": p.AssetIDs, "confirmed_by": by},
			"named human re-confirmed a product's scope")
	}
	writeJSON(w, http.StatusOK, p)
}

func (d Deps) handleDeleteProduct(w http.ResponseWriter, r *http.Request, tenantID string) {
	pid := r.PathValue("id")
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := make([]platform.Product, 0, len(t.Products))
	found := false
	for _, p := range t.Products {
		if p.ID == pid {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("product not found"))
		return
	}
	t.Products = kept
	if err := d.Store.PutTenant(ctx, t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("product removed", "product_scope", map[string]any{"tenant_id": tenantID, "product_id": pid}, "product scope removed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": pid})
}

// handleSetScope marks an asset out of scope (with who and why) or brings it back.
func (d Deps) handleSetScope(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		AssetID    string `json:"asset_id"`
		OutOfScope bool   `json:"out_of_scope"`
		By         string `json:"by"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	aid := strings.TrimSpace(body.AssetID)
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	exists := false
	for _, a := range assets {
		if a.ID == aid {
			exists = true
		}
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, errBody("asset not found"))
		return
	}
	if body.OutOfScope {
		by := strings.TrimSpace(body.By)
		if by == "" {
			writeJSON(w, http.StatusBadRequest, errBody("by is required: a named person must decide an asset is out of scope"))
			return
		}
		for _, p := range t.Products {
			for _, id := range p.AssetIDs {
				if id == aid {
					writeJSON(w, http.StatusBadRequest, errBody("this asset is part of "+p.Name+" — remove it from that product first"))
					return
				}
			}
		}
		if t.OutOfScope == nil {
			t.OutOfScope = map[string]platform.ScopeExclusion{}
		}
		t.OutOfScope[aid] = platform.ScopeExclusion{By: by, Reason: strings.TrimSpace(body.Reason), At: time.Now().UTC()}
	} else {
		delete(t.OutOfScope, aid)
	}
	if err := d.Store.PutTenant(ctx, t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("asset scope changed", "product_scope",
			map[string]any{"tenant_id": tenantID, "asset_id": aid, "out_of_scope": body.OutOfScope, "by": body.By, "reason": body.Reason},
			"asset scope decision")
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": aid, "out_of_scope": body.OutOfScope})
}

// productScopeFor resolves ?product=<id> into a report scope. ok=false with found=false means the id
// names no product of this tenant.
func productScopeFor(t platform.Tenant, pid string) (*grc.ProductScope, bool) {
	for _, p := range t.Products {
		if p.ID == pid {
			return &grc.ProductScope{Name: p.Name, AssetIDs: append([]string(nil), p.AssetIDs...),
				ConfirmedBy: p.ConfirmedBy, ConfirmedAt: p.ConfirmedAt}, true
		}
	}
	return nil, false
}

func isExcluded(out map[string]platform.ScopeExclusion, id string) bool {
	_, ok := out[id]
	return ok
}
