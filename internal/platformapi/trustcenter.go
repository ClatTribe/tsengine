package platformapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/trustcenter"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The Trust Center's document tier — the half that turns the security review from a call into
// a link. internal/platformapi/trust.go serves the aggregate posture page; this file serves the
// documents behind it, the buyer access flow, and the owner's desk.
//
// Every artifact offered here already existed and was unreachable: the VAPT report, the
// per-framework compliance report, the auto-answered questionnaire and the signed evidence
// pack were all authenticated, tenant-only endpoints. A buyer could not be shown any of them
// without someone exporting a file and mailing it, which is the two-hour call this feature
// exists to delete.
//
// The whole surface is arranged around one asymmetry. The reader is a stranger doing vendor
// due diligence, so an over-claim here is both maximally consequential and minimally
// correctable — there is no product context around the page to walk it back. Hence: nothing is
// listed that cannot be produced, nothing naming an open finding is ever public, and every
// generated document is stamped with who it was issued to and when it was generated.

// trustRequestLimiter bounds the public access-request endpoint. Stricter than the assess
// limiter because this one CREATES records: unbounded, a script could bury an owner's desk in
// requests until the real buyer's is invisible, which is a denial of the feature rather than of
// the service.
var trustRequestLimiter = &assessLimiter{hit: map[string][]time.Time{}, max: 5}

// --- owner side -------------------------------------------------------------------------

type trustSettingsView struct {
	Config platform.TrustCenterConfig `json:"config"`
	// Link is the shareable path, regenerated from the current token version.
	Link string `json:"link"`
	// Available reports which configured documents can actually be produced right now, so the
	// owner sees what a buyer would see rather than what they configured. A row they added and
	// cannot yet back is the thing they most need told about, and it is invisible on the public
	// page by design.
	Available map[string]bool `json:"available"`
	// Unavailable names the configured documents that are NOT being shown, and why. Without it
	// the honest omission reads as a bug: the owner added a compliance report, the page does not
	// list it, and nothing says the framework has no assessed controls yet.
	Unavailable []trustUnavailable `json:"unavailable,omitempty"`
	Pending     int                `json:"pending_requests"`
}

type trustUnavailable struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

func (d Deps) handleGetTrustSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	cfg := trustConfigOf(t)
	avail, why := d.trustAvailability(r.Context(), tenantID, cfg)

	var missing []trustUnavailable
	for _, doc := range cfg.Documents {
		k := trustcenter.DocumentKey(doc)
		if avail[k] {
			continue
		}
		reason := why[k]
		if reason == "" {
			reason = "not available yet"
		}
		missing = append(missing, trustUnavailable{Key: k, Title: trustcenter.DocumentTitle(doc), Reason: reason})
	}

	reqs, _ := d.Store.ListTrustAccessRequests(r.Context(), tenantID)
	pending := 0
	for _, q := range reqs {
		if q.Status == platform.TrustReqPending {
			pending++
		}
	}
	writeJSON(w, http.StatusOK, trustSettingsView{
		Config: cfg, Link: d.trustPath(tenantID, cfg), Available: avail,
		Unavailable: missing, Pending: pending,
	})
}

func (d Deps) handlePutTrustSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var in platform.TrustCenterConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read the trust-center settings"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// The token version is NOT client-settable. It is the revocation counter; letting a config
	// save move it would either revoke every outstanding link by accident on a round-trip that
	// dropped the field, or let a stale client resurrect a link the owner had just killed.
	in.TokenVersion = trustConfigOf(t).TokenVersion

	cfg, corrections := trustcenter.NormalizeConfig(in)
	t.TrustCenter = &cfg
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("trust center updated", "trust_center_config",
			map[string]any{"tenant_id": tenantID, "enabled": cfg.Enabled, "documents": len(cfg.Documents), "corrections": len(corrections)},
			"trust center configuration changed")
	}
	avail, _ := d.trustAvailability(r.Context(), tenantID, cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"config": cfg, "link": d.trustPath(tenantID, cfg), "available": avail,
		// Corrections ride back on the SAVE, not only on the next GET. A config silently altered
		// is one the owner believes says something it does not — and on this page that belief is
		// about whether a document naming their open findings is public.
		"corrections": corrections,
	})
}

// handleRevokeTrustLink bumps the token version, invalidating every outstanding share link for
// this tenant and only this tenant.
//
// Before this existed the share token was a bare HMAC over the tenant id, so it was permanent:
// the only way to invalidate one was rotating the platform secret, which would have taken every
// other tenant's link — and, since that secret also keys the OAuth state, a good deal more —
// down with it. The public page told readers a link "has been revoked", describing something
// the product could not do.
func (d Deps) handleRevokeTrustLink(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	cfg := trustConfigOf(t)
	if cfg.TokenVersion == 0 {
		cfg.TokenVersion = 1 // 0 and 1 mint the same token, so step past both
	}
	cfg.TokenVersion++
	t.TrustCenter = &cfg
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("trust center link revoked", "trust_center_revoke",
			map[string]any{"tenant_id": tenantID, "token_version": cfg.TokenVersion}, "trust center share link rotated")
	}
	writeJSON(w, http.StatusOK, map[string]any{"link": d.trustPath(tenantID, cfg), "token_version": cfg.TokenVersion})
}

// handleListTrustRequests is the owner's desk. Token hashes never leave the server: they are
// the only thing standing between a stored record and working access to the document tier.
func (d Deps) handleListTrustRequests(w http.ResponseWriter, r *http.Request, tenantID string) {
	reqs, err := d.Store.ListTrustAccessRequests(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	t, _ := d.Store.GetTenant(r.Context(), tenantID)
	nda := trustcenter.RequiresNDA(trustConfigOf(t))
	now := time.Now().UTC()

	out := make([]map[string]any, 0, len(reqs))
	for _, q := range trustcenter.PendingFirst(reqs) {
		q.TokenHash = ""
		out = append(out, map[string]any{
			"request": q,
			// Granted is computed rather than inferred from Status by the client: a request can
			// be approved and still ungranted (expired, revoked, NDA outstanding), and a desk
			// that showed "approved" for all of those would misreport who currently has access.
			"granted": q.Granted(nda, now),
			"views":   len(q.Views),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out, "nda_required": nda})
}

// handleDecideTrustRequest is the approve/deny gate. On approval it returns the buyer's access
// token ONCE — it is stored only as a digest, so this response is the only chance to deliver it.
func (d Deps) handleDecideTrustRequest(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Decision string `json:"decision"` // approve | deny | revoke
		By       string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read the decision"))
		return
	}
	id := r.PathValue("id")
	req, ok, err := d.findTrustRequest(r.Context(), tenantID, id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("no such access request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	cfg := trustConfigOf(t)
	now := time.Now().UTC()

	resp := map[string]any{}
	switch strings.ToLower(strings.TrimSpace(body.Decision)) {
	case "approve":
		by := strings.TrimSpace(body.By)
		if by == "" {
			// A human approval with no human named is not one. The auto-approve path exists for
			// decisions a rule makes, and it marks them as such; leaving the name blank here
			// would make a person's decision indistinguishable from a rule's in the log.
			writeJSON(w, http.StatusBadRequest, errBody("name who is approving — the access log records it"))
			return
		}
		token, hash, err := trustcenter.NewAccessToken()
		if err != nil {
			respond(w, nil, err)
			return
		}
		req = trustcenter.Approve(cfg, req, by, false, now)
		req.TokenHash = hash
		resp["access_token"] = token
		resp["access_link"] = d.trustPath(tenantID, cfg) + "&access=" + token
		resp["shown_once"] = "This link is not stored and cannot be shown again. Send it to the requester now."
	case "deny":
		req = trustcenter.Deny(req, strings.TrimSpace(body.By), now)
	case "revoke":
		// Distinct from deny: this ends a grant that was live. Kept as its own verb so the log
		// can tell a request that was never approved from access that was withdrawn.
		req.Revoked = true
		req.DecidedBy = strings.TrimSpace(body.By)
	default:
		writeJSON(w, http.StatusBadRequest, errBody(`decision must be "approve", "deny" or "revoke"`))
		return
	}

	if err := d.Store.PutTrustAccessRequest(r.Context(), req); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("trust access "+req.Status, "trust_access_decision",
			map[string]any{"tenant_id": tenantID, "request_id": req.ID, "email": req.Email,
				"decision": body.Decision, "by": body.By, "revoked": req.Revoked},
			"trust center access decision")
	}
	req.TokenHash = ""
	resp["request"] = req
	writeJSON(w, http.StatusOK, resp)
}

// --- buyer side (PUBLIC, share-token gated) ----------------------------------------------

// handleTrustAccessRequest (PUBLIC) records a buyer's request to read the gated tier.
//
// What the buyer types about themselves is a CLAIM, never authentication — we send no
// confirmation mail, so an address here proves nothing. It is recorded as what was asserted;
// what actually gates access is the token minted at approval. The one place the claim carries
// weight is the auto-approve rule, which is why that is opt-in, per-domain, and never a
// wildcard.
func (d Deps) handleTrustAccessRequest(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	t, cfg, ok := d.trustTenantFor(r.Context(), tenant, r.URL.Query().Get("token"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	if !trustRequestLimiter.allow(clientIP(r), time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many requests — try again in a minute"))
		return
	}
	var body struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Company string `json:"company"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<19)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("could not read the request"))
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if trustcenter.EmailDomain(email) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a work email address is required"))
		return
	}
	now := time.Now().UTC()
	req := platform.TrustAccessRequest{
		ID: d.newID("treq"), TenantID: t.ID, Email: email,
		Name: strings.TrimSpace(body.Name), Company: strings.TrimSpace(body.Company),
		Reason: strings.TrimSpace(body.Reason), Status: platform.TrustReqPending, RequestedAt: now,
	}

	resp := map[string]any{"status": platform.TrustReqPending}
	if trustcenter.AutoApproves(cfg, email) {
		token, hash, err := trustcenter.NewAccessToken()
		if err != nil {
			respond(w, nil, err)
			return
		}
		req = trustcenter.Approve(cfg, req, "", true, now)
		req.TokenHash = hash
		resp["status"] = platform.TrustReqApproved
		resp["access_token"] = token
		resp["expires_at"] = req.ExpiresAt
	}
	if err := d.Store.PutTrustAccessRequest(r.Context(), req); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("trust access requested", "trust_access_request",
			map[string]any{"tenant_id": t.ID, "request_id": req.ID, "email": email,
				"company": req.Company, "auto_approved": req.AutoApproved},
			"trust center access requested")
	}
	resp["request_id"] = req.ID
	resp["nda_required"] = trustcenter.RequiresNDA(cfg)
	writeJSON(w, http.StatusOK, resp)
}

// handleTrustNDA (PUBLIC) records a buyer's click-through acceptance.
//
// The digest of the exact text they were shown is stored alongside the timestamp. Recording
// only "accepted" would be worthless the moment the tenant edited their terms: the record could
// not say which agreement was on screen. Same instinct as pinning a corpus version into a scan.
func (d Deps) handleTrustNDA(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	t, cfg, ok := d.trustTenantFor(r.Context(), tenant, r.URL.Query().Get("token"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&body)

	req, ok, err := d.trustRequestByToken(r.Context(), t.ID, r.URL.Query().Get("access"))
	if err != nil {
		respond(w, nil, err)
		return
	}
	if !ok || req.Status != platform.TrustReqApproved || req.Revoked {
		writeJSON(w, http.StatusForbidden, errBody("this access link is not valid"))
		return
	}
	if !trustcenter.RequiresNDA(cfg) {
		writeJSON(w, http.StatusBadRequest, errBody("this Trust Center does not require an agreement"))
		return
	}
	now := time.Now().UTC()
	req.NDAAcceptedAt = now
	req.NDAHash = trustcenter.NDAHash(cfg.NDAText)
	req.NDAName = strings.TrimSpace(body.Name)
	if err := d.Store.PutTrustAccessRequest(r.Context(), req); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("trust nda accepted", "trust_nda_accepted",
			map[string]any{"tenant_id": t.ID, "request_id": req.ID, "email": req.Email,
				"name": req.NDAName, "nda_hash": req.NDAHash, "at": now},
			"trust center agreement accepted")
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted_at": now, "nda_hash": req.NDAHash})
}

// handleTrustDocument (PUBLIC) serves one document to a visitor who may read it.
//
// Both gates are re-checked here rather than trusted from the listing: the catalog and this
// handler are separate paths over the same config, and the failure worth preventing is a row
// that renders locked while the endpoint behind it serves anyway. trustcenter.Find is the one
// decision both call.
func (d Deps) handleTrustDocument(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	t, cfg, ok := d.trustTenantFor(r.Context(), tenant, r.URL.Query().Get("token"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
		return
	}
	kind := platform.DocKind(strings.TrimSpace(r.URL.Query().Get("kind")))
	framework := strings.TrimSpace(r.URL.Query().Get("framework"))

	req, granted := d.trustGrant(r.Context(), t.ID, cfg, r.URL.Query().Get("access"))
	avail, _ := d.trustAvailability(r.Context(), t.ID, cfg)
	doc, allowed := trustcenter.Find(cfg, kind, framework, avail, granted)
	if !allowed {
		// One response for "no such document", "not available", and "not for you". Telling an
		// ungranted visitor which of the three applies would confirm the document exists, which
		// is the fact the gate is there to withhold.
		writeJSON(w, http.StatusForbidden, errBody("this document is not available to you"))
		return
	}

	if !doc.Kind.Generated() {
		http.Redirect(w, r, doc.URL, http.StatusFound)
		d.recordTrustView(r.Context(), req, granted, kind, framework)
		return
	}

	body, err := d.renderTrustDocument(r.Context(), t, cfg, doc, req, granted)
	if err != nil {
		respond(w, nil, err)
		return
	}
	d.recordTrustView(r.Context(), req, granted, kind, framework)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", trustDocFilename(t.Name, doc)))
	_, _ = io.WriteString(w, body)
}

func trustDocFilename(org string, doc platform.TrustDocument) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == ' ' || r == '-' || r == '_':
			return '-'
		}
		return -1
	}, org)
	name := slug + "-" + string(doc.Kind)
	if doc.Framework != "" {
		name += "-" + doc.Framework
	}
	return name + ".md"
}

// renderTrustDocument produces a generated document's body, watermarked.
//
// The watermark is on every generated document a granted buyer receives, naming who it was
// issued to and when it was generated. It is the only control available for an artifact whose
// entire purpose is to be forwarded, and its second half is the honest one: these regenerate
// from live posture, so a copy read months later describes a state that has moved on. A public
// document gets no watermark — there is no recipient to name, and stamping "provided to an
// approved reviewer" on something anyone may read would be a false claim about how it travelled.
func (d Deps) renderTrustDocument(ctx context.Context, t platform.Tenant, cfg platform.TrustCenterConfig, doc platform.TrustDocument, req platform.TrustAccessRequest, granted bool) (string, error) {
	var b strings.Builder
	if granted && doc.Visibility == platform.VisGated {
		b.WriteString("> " + trustcenter.Watermark(t.Name, req.Email, time.Now().UTC()) + "\n\n")
	}
	switch doc.Kind {
	case platform.DocSubprocessors:
		b.WriteString(renderSubprocessors(t.Name, cfg.Subprocessors))
	case platform.DocPolicies:
		pols, err := d.Store.ListPolicies(ctx, t.ID)
		if err != nil {
			return "", err
		}
		b.WriteString(renderPolicySummary(t.Name, pols))
	case platform.DocQuestionnaire:
		if d.GRC == nil {
			return "", fmt.Errorf("compliance is not configured")
		}
		q, err := d.GRC.Questionnaire(ctx, t.ID)
		if err != nil {
			return "", err
		}
		b.WriteString(grc.RenderQuestionnaireMarkdown(q))
	case platform.DocComplianceReport:
		if d.GRC == nil {
			return "", fmt.Errorf("compliance is not configured")
		}
		rep, err := d.GRC.Report(ctx, t.ID, doc.Framework)
		if err != nil {
			return "", err
		}
		b.WriteString(grc.RenderMarkdown(rep))
	case platform.DocVAPTReport:
		if d.GRC == nil {
			return "", fmt.Errorf("compliance is not configured")
		}
		rep, err := d.GRC.VAPTReport(ctx, t.ID)
		if err != nil {
			return "", err
		}
		// The same honesty pass the authenticated VAPT endpoint runs. Skipping it here would
		// mean the copy we hand a BUYER is the one that closes "every monitored asset is
		// currently clean" over scope nothing assessed — the reverse of where the caveats
		// matter most.
		rep.Untested = d.untestedScope(ctx, t.ID, rep.Scope)
		rep.PartiallyAssessed = d.partiallyAssessedScope(ctx, t.ID, rep.Scope)
		grc.Reassess(rep)
		stampIntel(rep, time.Now().UTC())
		stampDetection(rep, d.ScanImage, time.Now().UTC())
		b.WriteString(grc.RenderVAPTMarkdown(rep))
	case platform.DocEvidencePack:
		if d.GRC == nil {
			return "", fmt.Errorf("compliance is not configured")
		}
		pack, err := d.GRC.EvidencePack(ctx, t.ID, doc.Framework)
		if err != nil {
			return "", err
		}
		raw, err := json.MarshalIndent(pack, "", "  ")
		if err != nil {
			return "", err
		}
		b.WriteString("# Signed evidence pack — " + doc.Framework + "\n\n")
		b.WriteString("The signature covers the canonical JSON below. Verify it rather than take it on trust.\n\n")
		b.WriteString("```json\n" + string(raw) + "\n```\n")
	default:
		return "", fmt.Errorf("no renderer for %s", doc.Kind)
	}
	return b.String(), nil
}

func renderSubprocessors(org string, subs []platform.Subprocessor) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sub-processors — %s\n\n", org)
	b.WriteString("Third parties that process customer data on our behalf (GDPR Art. 28).\n\n")
	b.WriteString("| Sub-processor | Purpose | Location |\n|---|---|---|\n")
	for _, s := range subs {
		name := s.Name
		if s.URL != "" {
			name = fmt.Sprintf("[%s](%s)", s.Name, s.URL)
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", name, orDash(s.Purpose), orDash(s.Location))
	}
	return b.String()
}

func renderPolicySummary(org string, pols []platform.Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security policies — %s\n\n", org)
	// PUBLISHED only. A draft is a document nobody has adopted; listing it would tell a buyer a
	// control is in place because somebody started writing about it.
	published := make([]platform.Policy, 0, len(pols))
	for _, p := range pols {
		if p.Status == platform.PolicyPublished {
			published = append(published, p)
		}
	}
	sort.Slice(published, func(i, j int) bool { return published[i].Name < published[j].Name })
	if len(published) == 0 {
		b.WriteString("_No policies have been published yet._\n")
		return b.String()
	}
	b.WriteString("| Policy | Owner | Published |\n|---|---|---|\n")
	for _, p := range published {
		when := "—"
		if !p.PublishedAt.IsZero() {
			when = p.PublishedAt.UTC().Format("2 Jan 2006")
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", p.Name, orDash(p.Owner), when)
	}
	b.WriteString("\nPolicy documents are available on request under the agreement above.\n")
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// --- shared plumbing ---------------------------------------------------------------------

func trustConfigOf(t platform.Tenant) platform.TrustCenterConfig {
	if t.TrustCenter == nil {
		return platform.TrustCenterConfig{}
	}
	return *t.TrustCenter
}

func (d Deps) trustPath(tenantID string, cfg platform.TrustCenterConfig) string {
	return "/trust/" + tenantID + "?token=" + d.trustTokenFor(tenantID, cfg)
}

// trustTenantFor resolves a public request's tenant, verifying the share token.
func (d Deps) trustTenantFor(ctx context.Context, tenantID, token string) (platform.Tenant, platform.TrustCenterConfig, bool) {
	if tenantID == "" || token == "" {
		return platform.Tenant{}, platform.TrustCenterConfig{}, false
	}
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return platform.Tenant{}, platform.TrustCenterConfig{}, false
	}
	cfg := trustConfigOf(t)
	if subtle.ConstantTimeCompare([]byte(token), []byte(d.trustTokenFor(tenantID, cfg))) != 1 {
		return platform.Tenant{}, platform.TrustCenterConfig{}, false
	}
	return t, cfg, true
}

// trustGrant resolves an access token to its request and whether it currently grants access.
// A missing or unknown token is simply ungranted — never an error, because the ungated page is
// a legitimate way to arrive.
func (d Deps) trustGrant(ctx context.Context, tenantID string, cfg platform.TrustCenterConfig, token string) (platform.TrustAccessRequest, bool) {
	req, ok, err := d.trustRequestByToken(ctx, tenantID, token)
	if err != nil || !ok {
		return platform.TrustAccessRequest{}, false
	}
	return req, req.Granted(trustcenter.RequiresNDA(cfg), time.Now().UTC())
}

func (d Deps) trustRequestByToken(ctx context.Context, tenantID, token string) (platform.TrustAccessRequest, bool, error) {
	if strings.TrimSpace(token) == "" {
		return platform.TrustAccessRequest{}, false, nil
	}
	want := trustcenter.HashToken(token)
	reqs, err := d.Store.ListTrustAccessRequests(ctx, tenantID)
	if err != nil {
		return platform.TrustAccessRequest{}, false, err
	}
	for _, q := range reqs {
		// Constant-time even though both sides are digests: the comparison still leaks a prefix
		// length under timing, and there is no reason to hand that away.
		if q.TokenHash != "" && subtle.ConstantTimeCompare([]byte(q.TokenHash), []byte(want)) == 1 {
			return q, true, nil
		}
	}
	return platform.TrustAccessRequest{}, false, nil
}

func (d Deps) findTrustRequest(ctx context.Context, tenantID, id string) (platform.TrustAccessRequest, bool, error) {
	reqs, err := d.Store.ListTrustAccessRequests(ctx, tenantID)
	if err != nil {
		return platform.TrustAccessRequest{}, false, err
	}
	for _, q := range reqs {
		if q.ID == id {
			return q, true, nil
		}
	}
	return platform.TrustAccessRequest{}, false, nil
}

// recordTrustView appends to the grant's access log. Best-effort: a failed write must not deny
// a document to a buyer who is entitled to it, but it is the security record for artifacts that
// leave the building, so it is attempted on every open.
func (d Deps) recordTrustView(ctx context.Context, req platform.TrustAccessRequest, granted bool, kind platform.DocKind, framework string) {
	if !granted || req.ID == "" {
		return
	}
	_ = d.Store.PutTrustAccessRequest(ctx, trustcenter.RecordView(req, kind, framework, time.Now().UTC()))
}

// trustAvailability reports which configured documents can actually be produced, and for those
// that cannot, why.
//
// This is refusal (2) made operational: a document is listed only when it exists. The reason
// string is for the OWNER — the public page shows nothing at all, because a locked row asserts
// the document exists and is merely withheld, and that assertion has to be earned.
//
// Every check reads real state. None of them infers availability from the absence of a problem:
// "no findings" and "never scanned" produce the same empty list, and the second must not read
// as a document we can stand behind.
func (d Deps) trustAvailability(ctx context.Context, tenantID string, cfg platform.TrustCenterConfig) (trustcenter.Availability, map[string]string) {
	avail := trustcenter.Availability{}
	why := map[string]string{}

	scanned := d.tenantHasCompletedScan(ctx, tenantID)
	for _, doc := range cfg.Documents {
		key := trustcenter.DocumentKey(doc)
		switch doc.Kind {
		case platform.DocExternal:
			avail[key] = doc.URL != ""
			if !avail[key] {
				why[key] = "no link configured"
			}
		case platform.DocSubprocessors:
			avail[key] = len(cfg.Subprocessors) > 0
			if !avail[key] {
				why[key] = "no sub-processors listed yet"
			}
		case platform.DocPolicies:
			pols, err := d.Store.ListPolicies(ctx, tenantID)
			if err != nil {
				why[key] = "could not read your policies"
				continue
			}
			for _, p := range pols {
				if p.Status == platform.PolicyPublished {
					avail[key] = true
					break
				}
			}
			if !avail[key] {
				why[key] = "no policy has been published yet — drafts are not shown"
			}
		case platform.DocQuestionnaire:
			// The questionnaire always renders; its own honesty layer answers "Not assessed"
			// where no evidence source is connected, so it degrades in the document rather than
			// disappearing. Gated on GRC being configured at all, which is a deployment fact.
			avail[key] = d.GRC != nil
			if !avail[key] {
				why[key] = "compliance is not configured on this deployment"
			}
		case platform.DocVAPTReport:
			avail[key] = d.GRC != nil && scanned
			if !avail[key] {
				why[key] = "no scan has completed yet, so there is nothing to report on"
			}
		case platform.DocComplianceReport, platform.DocEvidencePack:
			if d.GRC == nil {
				why[key] = "compliance is not configured on this deployment"
				continue
			}
			if doc.Framework == "" {
				why[key] = "no framework selected"
				continue
			}
			cov, err := d.GRC.Coverage(ctx, tenantID, doc.Framework)
			// AssessedControls is the same signal the public posture page uses to decide
			// whether to list a framework at all. Zero means nothing has touched a control of
			// this framework — a report over it would be a page of headings.
			avail[key] = err == nil && cov.AssessedControls > 0
			if !avail[key] {
				why[key] = "no control of this framework has been assessed yet"
			}
		case platform.DocOverview:
			avail[key] = true
		default:
			why[key] = "unknown document kind"
		}
	}
	return avail, why
}
