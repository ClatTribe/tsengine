package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/hris"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// hrissettings.go is the per-tenant HR-SYSTEM source (Bucket B) and the sync that turns it into the
// joiner/leaver join. The product could see accounts (operate) and never employment; with an HRIS
// connected it can say "this person left in June and their admin account is still enabled" — the
// evidence an auditor asks for first (SOC 2 CC1.4 / CC6.2 / CC6.3). Credentials are sealed and never
// returned; the roster itself is stored per source (Store.ReplaceEmployees) so the runner can
// re-join it against the identity provider on every monitoring pass, not only on the Sync button.

type hrisSettingsView struct {
	Provider        string   `json:"provider"`
	HasKey          bool     `json:"has_key"`
	HasAccountToken bool     `json:"has_account_token"`
	Employees       int      `json:"employees"`
	LastSyncedAt    string   `json:"last_synced_at,omitempty"`
	Providers       []string `json:"providers"`
}

func (d Deps) hrisView(ctx context.Context, t platform.Tenant) hrisSettingsView {
	v := hrisSettingsView{Providers: hris.Providers()}
	if t.HRIS != nil {
		v.Provider = t.HRIS.Provider
		v.HasKey, v.HasAccountToken = t.HRIS.KeyRef != "", t.HRIS.AccountTokenRef != ""
	}
	if emps, err := d.Store.ListEmployees(ctx, t.ID); err == nil {
		v.Employees = len(emps)
		var latest time.Time
		for _, e := range emps {
			if e.FetchedAt.After(latest) {
				latest = e.FetchedAt
			}
		}
		if !latest.IsZero() {
			v.LastSyncedAt = latest.UTC().Format(time.RFC3339)
		}
	}
	return v
}

func (d Deps) handleGetHRISSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.hrisView(r.Context(), t))
}

// handlePutHRISSettings sets the tenant's HR source. Empty credential fields keep the sealed ones;
// an empty provider clears the config (the stored roster is kept — it is evidence about a moment,
// and deleting it would make past findings uncitable).
func (d Deps) handlePutHRISSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Provider     string `json:"provider"`
		APIKey       string `json:"api_key"`
		AccountToken string `json:"account_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	provider := strings.ToLower(strings.TrimSpace(body.Provider))
	if provider == "" {
		t.HRIS = nil
		if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
			return
		}
		writeJSON(w, http.StatusOK, d.hrisView(r.Context(), t))
		return
	}
	if !hris.ValidProvider(provider) {
		writeJSON(w, http.StatusBadRequest, errBody("provider must be one of "+strings.Join(hris.Providers(), ", ")))
		return
	}
	cfg := &platform.HRISConfig{Provider: provider}
	if t.HRIS != nil && t.HRIS.Provider == provider {
		cfg.KeyRef, cfg.AccountTokenRef = t.HRIS.KeyRef, t.HRIS.AccountTokenRef
	}
	seal := func(plain, what string) (string, bool) {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return "", false
		}
		ref, serr := d.Vault.Seal(plain)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the "+what))
			return "", false
		}
		return ref, true
	}
	if k := strings.TrimSpace(body.APIKey); k != "" {
		ref, ok := seal(k, "API key")
		if !ok {
			return
		}
		cfg.KeyRef = ref
	}
	if a := strings.TrimSpace(body.AccountToken); a != "" {
		ref, ok := seal(a, "account token")
		if !ok {
			return
		}
		cfg.AccountTokenRef = ref
	}
	if !cfg.HasCredential() {
		if provider == platform.HRISMerge {
			writeJSON(w, http.StatusBadRequest, errBody("merge needs the api_key and the linked-account account_token"))
		} else {
			writeJSON(w, http.StatusBadRequest, errBody("finch needs the employer access token (api_key)"))
		}
		return
	}
	t.HRIS = cfg
	if perr := d.Store.PutTenant(r.Context(), t); perr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(perr.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("HR-system source updated", "hris_config",
			map[string]any{"tenant_id": tenantID, "provider": cfg.Provider}, "tenant HRIS source configured")
	}
	writeJSON(w, http.StatusOK, d.hrisView(r.Context(), t))
}

// hrisFetcherFor builds the roster fetcher a tenant's HRIS config describes.
func (d Deps) hrisFetcherFor(t platform.Tenant) (hris.Fetcher, error) {
	if t.HRIS == nil {
		return nil, fmt.Errorf("no HR-system source configured")
	}
	if d.Vault == nil {
		return nil, fmt.Errorf("secret vault unavailable")
	}
	hc := d.HRISHTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second} // fixed provider hosts — not tenant-controlled
	}
	return hris.New(t.HRIS, hris.Options{Open: d.Vault.Open, HTTP: hc, MergeBase: d.MergeAPIBase, FinchBase: d.FinchAPIBase})
}

// handleSyncHRIS is the LIVE roster sync: fetch employees from the HRIS, store them, and run the
// joiner/leaver join against every connected identity provider RIGHT NOW. The runner repeats the
// join on each monitoring pass from the stored roster (OperateRunner.Employees), so a leaver whose
// account is re-enabled next week is caught next week, not at the next click.
func (d Deps) handleSyncHRIS(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if t.HRIS == nil {
		writeJSON(w, http.StatusBadRequest, errBody("configure an HR-system source first (Settings → HR system)"))
		return
	}
	f, err := d.hrisFetcherFor(t)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	emps, frep, ferr := f.Fetch(r.Context())
	if ferr != nil {
		writeJSON(w, http.StatusBadGateway, errBody(ferr.Error()))
		return
	}
	for i := range emps {
		emps[i].TenantID = tenantID
	}
	if serr := d.Store.ReplaceEmployees(r.Context(), tenantID, frep.Provider, emps); serr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not store the roster: "+serr.Error()))
		return
	}
	// The stamp means "the roster was READ"; whether the join could run is reported separately
	// below, because a roster with no identity provider to join against is still a roster.
	d.markPostureAssessed(r.Context(), tenantID, "hris", time.Now().UTC())

	resp := map[string]any{
		"provider": frep.Provider, "source": "live", "employees": frep.Employees,
	}
	var notes []string
	if n := len(frep.Unread); n > 0 {
		notes = append(notes, fmt.Sprintf("%d employee record(s) could not be fully read (no address or dates), so they cannot be matched to an account: %s", n, strings.Join(capList(frep.Unread, 10), ", ")))
	}
	if frep.WithoutEmail > 0 {
		notes = append(notes, fmt.Sprintf("%d employee record(s) carry no email address and cannot be matched to any account", frep.WithoutEmail))
	}

	// The join, against every workspace asset (each connected IdP).
	findings, joinNotes, joined := d.correlateHRIS(r.Context(), tenantID, emps)
	notes = append(notes, joinNotes...)
	resp["findings"] = findings
	resp["issues_detected"] = len(findings)
	resp["joined"] = joined
	if len(notes) > 0 {
		resp["checks_not_run"] = notes
	}
	if d.Recorder != nil {
		d.Recorder.Record("HR roster synced", "hris_sync",
			map[string]any{"tenant_id": tenantID, "provider": frep.Provider, "employees": frep.Employees, "findings": len(findings)},
			"live HRIS sync + joiner/leaver join")
	}
	writeJSON(w, http.StatusOK, resp)
}

// correlateHRIS runs the join for every workspace asset the tenant has and stores the findings
// through the same enrich → fold → propose → incident path as every other ingest. Returns the
// stored findings, the disclosures owed, and whether any join actually ran.
func (d Deps) correlateHRIS(ctx context.Context, tenantID string, emps []platform.Employee) ([]types.Finding, []string, bool) {
	var notes []string
	if d.WorkspaceSource == nil {
		return []types.Finding{}, []string{"no identity-provider source is wired on this deployment, so the roster was stored but not checked against accounts"}, false
	}
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return []types.Finding{}, []string{"could not list assets: " + err.Error()}, false
	}
	var out []types.Finding
	joined := false
	for _, a := range assets {
		if a.Type != runner.WorkspaceType {
			continue
		}
		ws, werr := d.WorkspaceSource.Workspace(ctx, a)
		if werr != nil {
			notes = append(notes, fmt.Sprintf("%s could not be read (%v), so its accounts were not checked against employment", a.Target, werr))
			continue
		}
		fs, rep := hris.Correlate(emps, ws, hris.CorrelateOptions{})
		notes = append(notes, rep.ChecksNotRun...)
		if len(rep.ChecksNotRun) == 0 {
			joined = true
		}
		fs = enrichFindings(fs) // §11
		saved := make([]types.Finding, 0, len(fs))
		for _, f := range fs {
			f.ID = d.newID("hris")
			if serr := d.Store.PutFinding(ctx, tenantID, f); serr != nil {
				continue
			}
			saved = append(saved, f)
		}
		d.foldIntoPosture(ctx, tenantID, saved)
		// Propose against the WORKSPACE asset, not a bare one: remediate's identity runbooks (and the
		// live account-suspend promotion) key on asset type + provider, and a leaver's account is
		// exactly the finding that should reach the desk as a gated suspend rather than a generic ticket.
		d.proposeForFindingsOn(ctx, tenantID, a, saved)
		if d.IncidentOpener != nil && len(saved) > 0 {
			_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
		}
		out = append(out, saved...)
	}
	if !joined && len(notes) == 0 {
		notes = append(notes, "no identity provider is connected, so the roster was stored but no account could be checked against employment — connect Google Workspace, Microsoft 365 or Okta")
	}
	if out == nil {
		out = []types.Finding{}
	}
	return out, notes, joined
}
