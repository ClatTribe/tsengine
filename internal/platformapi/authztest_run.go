package platformapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleRunAuthzTest (POST /v1/assets/{id}/authz-test/run) EXECUTES the BOLA/BFLA differential
// test an owner previously configured via POST /v1/assets/{id}/authz-test. This is the missing
// execution half — configuration + LLM discovery already existed, but nothing ran the stored
// test against the live API, so BOLA/BFLA (OWASP API #1/#3/#6) never actually fired.
//
// The test is ACTIVE by nature (it replays the victim's request as the attacker — the §13 no-OSS
// authz exception), so it is double-gated:
//
//  1. Per-request explicit consent — allow_active + authorized_by + consent, the SAME
//     RulesOfEngagement.ActiveAuthorized() triplet the pentest driver requires. The consent
//     statement is signed into the ledger.
//  2. Operator enablement — d.AuthzProber is wired only when TSENGINE_ACTIVE_EXPLOIT=1
//     (apiauthz.LiveProber()). Nil → 403, active testing is off (never a silent no-op).
//
// A confirmed bypass is grounded (apiauthz.Evaluate proves a 2xx-with-victim-data / undenied
// privileged call), enriched through the L1.5 chain like any finding, and stored so it flows into
// issues/incidents/grc/hitl. The identities' auth headers are never echoed in the response.
func (d Deps) handleRunAuthzTest(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")

	var body struct {
		AllowActive  bool   `json:"allow_active"`
		AuthorizedBy string `json:"authorized_by"`
		Consent      string `json:"consent"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid run request"))
		return
	}
	// Gate 1: explicit consent. Active authz testing replays requests as an attacker identity —
	// it needs the same named-authorization + recorded-consent as active exploitation.
	roe := pentest.RulesOfEngagement{AllowActive: body.AllowActive, AuthorizedBy: body.AuthorizedBy, Consent: body.Consent}
	if !roe.ActiveAuthorized() {
		writeJSON(w, http.StatusForbidden, errBody("active BOLA/BFLA testing requires explicit consent: allow_active + authorized_by + consent"))
		return
	}
	// Gate 2: operator enablement. No live prober → active testing is disabled deployment-wide.
	if d.AuthzProber == nil {
		writeJSON(w, http.StatusForbidden, errBody("live active testing is not enabled by the operator (TSENGINE_ACTIVE_EXPLOIT)"))
		return
	}

	assets, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var found *platform.Asset
	for i := range assets {
		if assets[i].ID == id {
			found = &assets[i]
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, errBody("asset not found"))
		return
	}

	sealed := found.Meta["authz_test"]
	if sealed == "" {
		writeJSON(w, http.StatusBadRequest, errBody("no BOLA/BFLA test configured for this asset — POST /v1/assets/{id}/authz-test first"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusBadRequest, errBody("secret vault not configured — cannot open the sealed authz-test config"))
		return
	}
	blob, oerr := d.Vault.Open(sealed)
	if oerr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("open authz-test config: "+oerr.Error()))
		return
	}
	var cfg apiauthz.TestConfig
	if err := json.Unmarshal([]byte(blob), &cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("stored authz-test config is corrupt"))
		return
	}
	if err := cfg.Valid(); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("stored authz-test config invalid: "+err.Error()))
		return
	}

	plan := apiauthz.Plan(cfg.Operations, cfg.Victim, cfg.Attacker)
	n := 0
	idgen := func() string {
		n++
		return d.newID("authz") + "-" + strconv.Itoa(n)
	}
	findings := apiauthz.Run(r.Context(), plan, d.AuthzProber, idgen)
	findings = enrichFindings(findings) // L1.5 parity (§11): the same enrichment engine-scanned findings get

	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil {
		d.Recorder.Record("api authz test run", "authz_test_run",
			map[string]any{
				"tenant_id": tenantID, "asset_id": id, "target": found.Target,
				"authorized_by": body.AuthorizedBy, "consent": body.Consent,
				"operations": len(plan), "bypasses": stored,
			},
			"BOLA/BFLA differential test executed (consent-gated)")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":  id,
		"tests_run": len(plan),
		"bypasses":  stored,
		"findings":  saved,
	})
}
