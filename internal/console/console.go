// Package console is the human-facing web UI for the autonomous security team — the
// "from UX" surface a founder / IT-generalist actually looks at (docs/autonomous-team.md
// §3.7). It is server-rendered HTML (html/template, zero JS framework, no build step),
// served by cmd/platform alongside the JSON API. One screen answers "am I okay?":
// posture by framework, open findings by severity, and the actions waiting on a human —
// each with Approve / Reject buttons so the human-in-the-loop closes in the browser.
//
// Auth: the console shares the platform bearer token. A browser can't send an
// Authorization header on a plain navigation, so the console also accepts a session
// cookie set by a tiny login form (POST /ui/login). The cookie is httpOnly +
// SameSite=Strict (the CSRF defence for the POST actions) + Secure over TLS.
//
// Acting on an approval does NOT bypass the gate: the Approve/Reject buttons drive the
// same hitl.Desk.Decide path the API and Slack use, so tier rules + the signed ledger
// still apply. The console is a UI onto the gated decision, not a second write path.
package console

import (
	"context"
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

const (
	sessionCookie  = "ts_session"  // value = the platform token (httpOnly, SameSite=Strict)
	operatorCookie = "ts_operator" // optional human name, used as the ledger approver
)

// Decider is the gated HITL surface the console drives (satisfied by *hitl.Desk). The
// console never applies a fix itself — it hands the verdict to the desk.
type Decider interface {
	Decide(ctx context.Context, tenantID, actionID string, v hitl.Verdict) (platform.Action, error)
}

// Reporter is the GRC surface the compliance drill-down needs (satisfied by *grc.GRC).
type Reporter interface {
	Report(ctx context.Context, tenantID, framework string) (*grc.Report, error)
}

// ConnectorSource lists the available connectors and resolves one by kind so the connect
// page can offer them and kick off OAuth (satisfied by *connector.Registry).
type ConnectorSource interface {
	Kinds() []string
	Get(kind string) (connector.Connector, error)
}

// Rescanner re-scans every asset a tenant has (satisfied by *runner.Service). Optional:
// when set, the dashboard offers a "Scan now" button.
type Rescanner interface {
	RescanTenant(ctx context.Context, tenantID string) (int, error)
}

// Deps are the console's read collaborators plus the gated desk for approvals.
type Deps struct {
	Store      store.Store
	Token      string          // platform bearer token (same as the API)
	Desk       Decider         // gated approval path; nil → Approve/Reject return 501
	Report     Reporter        // compliance drill-down; nil → posture cards are not linked
	Connectors ConnectorSource // onboarding; nil → the connect page/link is hidden
	PublicURL  string          // base URL for the OAuth redirect_uri (e.g. https://app.example)
	Rescan     Rescanner       // manual "scan now"; nil → the button is hidden
}

// Handler returns the console router: the dashboard, the login form, logout, and the
// gated approve/reject actions, all under /ui. Mount it at both "/ui" and "/ui/".
func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ui", d.dashboard)
	mux.HandleFunc("GET /ui/findings/{id}", d.finding)
	mux.HandleFunc("GET /ui/compliance/{framework}", d.compliance)
	mux.HandleFunc("GET /ui/connect", d.connectPage)
	mux.HandleFunc("GET /ui/connect/{kind}", d.connect)
	mux.HandleFunc("POST /ui/login", d.login)
	mux.HandleFunc("POST /ui/logout", d.logout)
	mux.HandleFunc("POST /ui/approvals/{id}", d.decide)
	mux.HandleFunc("POST /ui/rescan", d.rescan)
	return mux
}

// dashboard renders the posture screen, or the login page when unauthenticated, or a
// tenant picker when authenticated without a chosen tenant.
func (d Deps) dashboard(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusOK, loginView{Tenant: r.URL.Query().Get("tenant")})
		return
	}
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		d.renderTenantPicker(w, r)
		return
	}
	vm, err := build(r.Context(), d.Store, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vm.Operator = cookieValue(r, operatorCookie)
	vm.CanApprove = d.Desk != nil
	vm.CanReport = d.Report != nil
	vm.CanConnect = d.Connectors != nil
	vm.CanRescan = d.Rescan != nil
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, vm); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// connectPage lists the available connectors with the tenant's current connection count
// and a Connect button — the first-run self-serve onboarding surface.
func (d Deps) connectPage(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusOK, loginView{Tenant: r.URL.Query().Get("tenant")})
		return
	}
	if d.Connectors == nil {
		http.Error(w, "connectors not configured", http.StatusNotImplemented)
		return
	}
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		http.Error(w, "missing tenant (?tenant=<id>)", http.StatusBadRequest)
		return
	}
	conns, _ := d.Store.ListConnections(r.Context(), tenantID)
	countByKind := map[string]int{}
	for _, c := range conns {
		countByKind[c.Kind]++
	}
	cv := connectView{TenantID: tenantID, Tenant: tenantID}
	if t, err := d.Store.GetTenant(r.Context(), tenantID); err == nil && t.Name != "" {
		cv.Tenant = t.Name
	}
	kinds := d.Connectors.Kinds()
	sort.Strings(kinds)
	for _, k := range kinds {
		cv.Rows = append(cv.Rows, connectRow{Kind: k, Name: connectorName(k), Connected: countByKind[k]})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := connectPg.Execute(w, cv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// connect kicks off the provider OAuth consent: it builds the authorize URL (CSRF state =
// tenant id, the form the /v1/connect/{kind}/callback handler already expects) and
// redirects the browser. The callback exchanges the code, seals the token, and scans.
func (d Deps) connect(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusOK, loginView{Tenant: r.URL.Query().Get("tenant")})
		return
	}
	if d.Connectors == nil {
		http.Error(w, "connectors not configured", http.StatusNotImplemented)
		return
	}
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		http.Error(w, "missing tenant (?tenant=<id>)", http.StatusBadRequest)
		return
	}
	c, err := d.Connectors.Get(r.PathValue("kind"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectURI := d.PublicURL + "/v1/connect/" + c.Kind() + "/callback"
	http.Redirect(w, r, c.OAuthURL(tenantID, redirectURI), http.StatusSeeOther)
}

// finding renders one finding's full detail — the evidence behind a dashboard row
// (description, status/confidence, CWE/MITRE, threat intel, compliance mapping).
func (d Deps) finding(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusOK, loginView{Tenant: r.URL.Query().Get("tenant")})
		return
	}
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		http.Error(w, "missing tenant (?tenant=<id>)", http.StatusBadRequest)
		return
	}
	fs, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	var found *types.Finding
	for i := range fs {
		if fs[i].ID == id {
			found = &fs[i]
			break
		}
	}
	if found == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := findingPage.Execute(w, findingDetail(tenantID, *found)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type findingView struct {
	TenantID, ID, Title, Severity, Status, Tool, RuleID, Endpoint, Description string
	Confidence                                                                 float64
	CWE, MITRE, CorroboratedBy, Compliance                                     []string
	KEV                                                                        bool
	EPSS                                                                       string
}

// findingDetail flattens a types.Finding into the render model.
func findingDetail(tenantID string, f types.Finding) findingView {
	v := findingView{
		TenantID: tenantID, ID: f.ID, Title: f.Title, Severity: string(f.Severity),
		Status: string(f.VerificationStatus), Tool: f.Tool, RuleID: f.RuleID,
		Endpoint: f.Endpoint, Description: f.Description, Confidence: f.Confidence,
		CWE: f.CWE, MITRE: f.MITRETechniques, CorroboratedBy: f.CorroboratedBy,
	}
	if v.Status == "" {
		v.Status = string(types.VerificationPatternMatch)
	}
	if ti := f.ThreatIntel; ti != nil {
		v.KEV = ti.KEV != nil
		if ti.EPSS != nil {
			v.EPSS = "EPSS present"
		}
	}
	if c := f.Compliance; c != nil {
		add := func(name string, ctrls []string) {
			if len(ctrls) > 0 {
				v.Compliance = append(v.Compliance, name+": "+strings.Join(ctrls, ", "))
			}
		}
		add("SOC 2", c.SOC2)
		add("ISO 27001", c.ISO27001)
		add("PCI", c.PCI)
		add("HIPAA", c.HIPAA)
		add("CIS v8", c.CISv8)
		add("NIST CSF", c.NISTCSF)
	}
	return v
}

// compliance renders the per-framework drill-down: every tracked control, gaps backed by
// their citing findings — the auditor-facing view of the dashboard's posture card.
func (d Deps) compliance(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusOK, loginView{Tenant: r.URL.Query().Get("tenant")})
		return
	}
	if d.Report == nil {
		http.Error(w, "compliance reporting not configured", http.StatusNotImplemented)
		return
	}
	tenantID := firstNonEmpty(r.URL.Query().Get("tenant"), r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		http.Error(w, "missing tenant (?tenant=<id>)", http.StatusBadRequest)
		return
	}
	framework := r.PathValue("framework")
	if !grc.IsFramework(framework) {
		// An unknown framework must 404, never render a fabricated empty report (grounding §10).
		http.Error(w, "unknown compliance framework: "+framework, http.StatusNotFound)
		return
	}
	rep, err := d.Report.Report(r.Context(), tenantID, framework)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := compliancePage.Execute(w, rep); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// login validates the token, sets the session cookie, and redirects into the dashboard.
func (d Deps) login(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	if d.Token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(d.Token)) != 1 {
		renderLogin(w, http.StatusUnauthorized, loginView{Error: "Invalid token.", Tenant: r.FormValue("tenant")})
		return
	}
	secure := isHTTPS(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/ui",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure})
	if op := strings.TrimSpace(r.FormValue("operator")); op != "" {
		http.SetCookie(w, &http.Cookie{Name: operatorCookie, Value: op, Path: "/ui",
			SameSite: http.SameSiteStrictMode, Secure: secure})
	}
	http.Redirect(w, r, "/ui?tenant="+url.QueryEscape(r.FormValue("tenant")), http.StatusSeeOther)
}

// logout clears the session.
func (d Deps) logout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookie, operatorCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/ui", MaxAge: -1})
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

// decide records a human verdict on a pending action through the gated desk.
func (d Deps) decide(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusUnauthorized, loginView{Tenant: r.FormValue("tenant")})
		return
	}
	if d.Desk == nil {
		http.Error(w, "approvals not configured", http.StatusNotImplemented)
		return
	}
	tenantID := r.FormValue("tenant")
	if tenantID == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}
	approver := firstNonEmpty(cookieValue(r, operatorCookie), "console")
	_, err := d.Desk.Decide(r.Context(), tenantID, r.PathValue("id"),
		hitl.Verdict{Approver: approver, Approve: r.FormValue("decision") == "approve"})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/ui?tenant="+url.QueryEscape(tenantID), http.StatusSeeOther)
}

// rescan triggers an immediate re-scan of all the tenant's assets (the "scan now" button).
func (d Deps) rescan(w http.ResponseWriter, r *http.Request) {
	if !d.authed(r) {
		renderLogin(w, http.StatusUnauthorized, loginView{Tenant: r.FormValue("tenant")})
		return
	}
	if d.Rescan == nil {
		http.Error(w, "scanning not configured", http.StatusNotImplemented)
		return
	}
	tenantID := r.FormValue("tenant")
	if tenantID == "" {
		http.Error(w, "missing tenant", http.StatusBadRequest)
		return
	}
	if _, err := d.Rescan.RescanTenant(r.Context(), tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/ui?tenant="+url.QueryEscape(tenantID), http.StatusSeeOther)
}

// authed accepts either a valid bearer header (programmatic) or a valid session cookie
// (browser). Both compared in constant time.
func (d Deps) authed(r *http.Request) bool {
	if d.Token == "" {
		return false
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") &&
		subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(d.Token)) == 1 {
		return true
	}
	if c, err := r.Cookie(sessionCookie); err == nil &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(d.Token)) == 1 {
		return true
	}
	return false
}

func (d Deps) renderTenantPicker(w http.ResponseWriter, r *http.Request) {
	tenants, _ := d.Store.ListTenants(r.Context())
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].ID < tenants[j].ID })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pickerPage.Execute(w, tenants)
}

// view is the rendered dashboard model.
type view struct {
	TenantID    string
	Tenant      string
	RiskRating  string
	SevCounts   []sevCount
	Findings    []types.Finding
	Pending     []platform.Action
	Incidents   []platform.Incident
	Resolved    []platform.Incident
	Connections []platform.Connection
	Frameworks  []framework
	Assets      []assetRow
	Apps        []platform.ThirdPartyApp
	Operator    string
	CanApprove  bool
	CanReport   bool
	CanConnect  bool
	CanRescan   bool
}

// assetRow is one monitored asset with its last-scanned time.
type assetRow struct {
	Type     string
	Target   string
	LastScan string
}

// connectView models the onboarding page.
type connectView struct {
	TenantID string
	Tenant   string
	Rows     []connectRow
}

type connectRow struct {
	Kind      string
	Name      string
	Connected int
}

// connectorName maps a connector kind to its friendly display name.
func connectorName(kind string) string {
	switch kind {
	case platform.ConnGitHub:
		return "GitHub"
	case platform.ConnGitLab:
		return "GitLab"
	case platform.ConnGWorkspace:
		return "Google Workspace"
	case platform.ConnM365:
		return "Microsoft 365"
	default:
		if kind == "" {
			return "Unknown"
		}
		return strings.ToUpper(kind[:1]) + kind[1:]
	}
}

type sevCount struct {
	Severity string
	Count    int
	Class    string
}

type framework struct {
	Key  string // soc2 (for the drill-down link)
	Name string // SOC2 (display)
	Met  int
	Gap  int
}

func build(ctx context.Context, st store.Store, tenantID string) (view, error) {
	v := view{TenantID: tenantID, Tenant: tenantID}
	if t, err := st.GetTenant(ctx, tenantID); err == nil && t.Name != "" {
		v.Tenant = t.Name
	}
	findings, err := st.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return v, err
	}
	// severity tally + risk rating
	counts := map[types.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	for _, s := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		v.SevCounts = append(v.SevCounts, sevCount{Severity: string(s), Count: counts[s], Class: string(s)})
	}
	v.RiskRating = riskRating(counts)

	// top findings (worst first), capped for the overview
	sort.SliceStable(findings, func(i, j int) bool { return sevRank(findings[i].Severity) < sevRank(findings[j].Severity) })
	if len(findings) > 25 {
		findings = findings[:25]
	}
	v.Findings = findings

	v.Pending, _ = st.PendingApprovals(ctx, tenantID)
	// open incidents = "what's newly broken since the last monitoring pass";
	// resolved incidents = "what the agent caught and is now fixed" (the autonomy story).
	if incs, err := st.ListIncidents(ctx, tenantID); err == nil {
		for _, i := range incs {
			if i.Status == platform.IncidentOpen {
				v.Incidents = append(v.Incidents, i)
			} else if i.Status == platform.IncidentResolved {
				v.Resolved = append(v.Resolved, i)
			}
		}
		sort.SliceStable(v.Incidents, func(a, b int) bool { return v.Incidents[a].OpenedAt.After(v.Incidents[b].OpenedAt) })
		sort.SliceStable(v.Resolved, func(a, b int) bool { return v.Resolved[a].ResolvedAt.After(v.Resolved[b].ResolvedAt) })
		if len(v.Resolved) > 8 {
			v.Resolved = v.Resolved[:8] // a recent highlight, not the full history
		}
	}
	conns, _ := st.ListConnections(ctx, tenantID)
	for i := range conns {
		conns[i].SecretRef = "" // never render the token ref
	}
	v.Connections = conns

	// monitored assets + when each was last scanned (so the owner sees what's watched)
	assets, _ := st.ListAssets(ctx, tenantID)
	engs, _ := st.ListEngagements(ctx, tenantID)
	lastScan := map[string]time.Time{}
	for _, e := range engs {
		if e.CompletedAt.After(lastScan[e.AssetID]) {
			lastScan[e.AssetID] = e.CompletedAt
		}
	}
	for _, a := range assets {
		row := assetRow{Type: a.Type, Target: a.Target, LastScan: "never"}
		if t, ok := lastScan[a.ID]; ok && !t.IsZero() {
			row.LastScan = t.UTC().Format("2006-01-02 15:04 UTC")
		}
		v.Assets = append(v.Assets, row)
	}

	// third-party OAuth app inventory (admin/risky apps first)
	if apps, err := st.ListThirdPartyApps(ctx, tenantID); err == nil {
		sort.SliceStable(apps, func(a, b int) bool {
			if apps[a].AdminScope != apps[b].AdminScope {
				return apps[a].AdminScope // admin apps first
			}
			return apps[a].AppID < apps[b].AppID
		})
		v.Apps = apps
	}

	// compliance posture by framework (met vs gap). Iterate grc.Frameworks (the single
	// source of truth) so the fallback console shows the full set, not a stale hardcoded six.
	for _, fw := range grc.Frameworks {
		cs, _ := st.Posture(ctx, tenantID, fw)
		if len(cs) == 0 {
			continue
		}
		f := framework{Key: fw, Name: grc.FrameworkTitle(fw)}
		for _, c := range cs {
			if c.State == platform.ControlMet {
				f.Met++
			} else {
				f.Gap++
			}
		}
		v.Frameworks = append(v.Frameworks, f)
	}
	return v, nil
}

func riskRating(c map[types.Severity]int) string {
	switch {
	case c[types.SeverityCritical] > 0:
		return "Critical"
	case c[types.SeverityHigh] > 0:
		return "High"
	case c[types.SeverityMedium] > 0:
		return "Medium"
	case c[types.SeverityLow] > 0:
		return "Low"
	default:
		return "Clear"
	}
}

func sevRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	}
	return 4
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

type loginView struct {
	Error  string
	Tenant string
}

func renderLogin(w http.ResponseWriter, code int, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = loginPage.Execute(w, v)
}

var (
	page           = template.Must(template.New("dash").Parse(pageHTML))
	loginPage      = template.Must(template.New("login").Parse(loginHTML))
	pickerPage     = template.Must(template.New("picker").Parse(pickerHTML))
	compliancePage = template.Must(template.New("compliance").Funcs(template.FuncMap{
		"rfc3339": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	}).Parse(complianceHTML))
	findingPage = template.Must(template.New("finding").Parse(findingHTML))
	connectPg   = template.Must(template.New("connect").Parse(connectHTML))
)
