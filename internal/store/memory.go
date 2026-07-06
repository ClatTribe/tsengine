package store

import (
	"context"
	"strings"
	"sync"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Memory is an in-memory, mutex-guarded Store for tests and the MVP. Tenant
// isolation is enforced by keying every collection on tenantID and never crossing
// it. A persistent (sqlite/Postgres) Store replaces this behind the same interface.
type Memory struct {
	mu sync.RWMutex

	tenants     map[string]platform.Tenant
	connections map[string][]platform.Connection               // tenantID → connections
	assets      map[string][]platform.Asset                    // tenantID → assets
	engagements map[string][]platform.Engagement               // tenantID → engagements
	findings    map[string][]types.Finding                     // tenantID → findings
	actions     map[string]map[string]platform.Action          // tenantID → actionID → action
	controls    map[string]map[string]platform.ControlState    // tenantID → "framework/control" → state
	incidents   map[string]map[string]platform.Incident        // tenantID → incidentID → incident
	risks       map[string]map[string]platform.Risk            // tenantID → riskID → risk
	aiAnalyses  map[string]map[string]platform.AIAnalysis      // tenantID → analysisID → AI analysis
	audits      map[string]map[string]platform.AuditEngagement // tenantID → engagementID → audit
	policies    map[string]map[string]platform.Policy          // tenantID → policyID → policy

	ignores     map[string]map[string]platform.IgnoreRule    // tenantID → issueKey → ignore rule
	exclusions  map[string]map[string]platform.ExclusionRule // tenantID → ruleID → exclusion rule
	runtimeEvts map[string][]platform.RuntimeEvent           // tenantID → runtime-protection events (append-only)
	pentests    map[string]map[string]pentest.Engagement     // tenantID → engagementID → pentest
	reviews     map[string]map[string]platform.ReviewRequest // tenantID → reviewID → review
	apps        map[string][]platform.ThirdPartyApp          // tenantID → third-party apps
	users       map[string]platform.User                     // userID → user (email globally unique)
	sessions    map[string]platform.Session                  // token → session
	operators   map[string]platform.Operator                 // operatorID → operator (cross-tenant; global)
	opSessions  map[string]platform.OperatorSession          // token → operator session
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tenants:     map[string]platform.Tenant{},
		connections: map[string][]platform.Connection{},
		assets:      map[string][]platform.Asset{},
		engagements: map[string][]platform.Engagement{},
		findings:    map[string][]types.Finding{},
		actions:     map[string]map[string]platform.Action{},
		controls:    map[string]map[string]platform.ControlState{},
		incidents:   map[string]map[string]platform.Incident{},
		risks:       map[string]map[string]platform.Risk{},
		aiAnalyses:  map[string]map[string]platform.AIAnalysis{},
		audits:      map[string]map[string]platform.AuditEngagement{},
		policies:    map[string]map[string]platform.Policy{},
		ignores:     map[string]map[string]platform.IgnoreRule{},
		exclusions:  map[string]map[string]platform.ExclusionRule{},
		runtimeEvts: map[string][]platform.RuntimeEvent{},
		pentests:    map[string]map[string]pentest.Engagement{},
		reviews:     map[string]map[string]platform.ReviewRequest{},
		apps:        map[string][]platform.ThirdPartyApp{},
		users:       map[string]platform.User{},
		sessions:    map[string]platform.Session{},
		operators:   map[string]platform.Operator{},
		opSessions:  map[string]platform.OperatorSession{},
	}
}

func (m *Memory) PutOperator(_ context.Context, o platform.Operator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operators[o.ID] = o
	return nil
}

func (m *Memory) GetOperator(_ context.Context, id string) (platform.Operator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.operators[id]
	if !ok {
		return platform.Operator{}, ErrNotFound
	}
	return o, nil
}

func (m *Memory) GetOperatorByEmail(_ context.Context, email string) (platform.Operator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	want := strings.ToLower(strings.TrimSpace(email))
	for _, o := range m.operators {
		if strings.ToLower(o.Email) == want {
			return o, nil
		}
	}
	return platform.Operator{}, ErrNotFound
}

func (m *Memory) PutOperatorSession(_ context.Context, s platform.OperatorSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opSessions[s.Token] = s
	return nil
}

func (m *Memory) GetOperatorSession(_ context.Context, token string) (platform.OperatorSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.opSessions[token]
	if !ok {
		return platform.OperatorSession{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteOperatorSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.opSessions, token)
	return nil
}

// --- users & sessions (real account auth) ---

func (m *Memory) PutUser(_ context.Context, u platform.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = u
	return nil
}

func (m *Memory) GetUser(_ context.Context, id string) (platform.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return platform.User{}, ErrNotFound
	}
	return u, nil
}

// GetUserByEmail looks a user up by email (case-insensitive). Email is globally unique.
func (m *Memory) GetUserByEmail(_ context.Context, email string) (platform.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	want := strings.ToLower(strings.TrimSpace(email))
	for _, u := range m.users {
		if strings.ToLower(u.Email) == want {
			return u, nil
		}
	}
	return platform.User{}, ErrNotFound
}

// ListUsers returns the members of a tenant.
func (m *Memory) ListUsers(_ context.Context, tenantID string) ([]platform.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.User
	for _, u := range m.users {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (m *Memory) PutSession(_ context.Context, s platform.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.Token] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, token string) (platform.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[token]
	if !ok {
		return platform.Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteSessionsForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, tok)
		}
	}
	return nil
}

func (m *Memory) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

func (m *Memory) PutTenant(_ context.Context, t platform.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[t.ID] = t
	return nil
}

func (m *Memory) GetTenant(_ context.Context, id string) (platform.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[id]
	if !ok {
		return platform.Tenant{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) ListTenants(_ context.Context) ([]platform.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	return out, nil
}

func (m *Memory) PutConnection(_ context.Context, c platform.Connection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connections[c.TenantID] = upsertByID(m.connections[c.TenantID], c, func(x platform.Connection) string { return x.ID })
	return nil
}

func (m *Memory) ListConnections(_ context.Context, tenantID string) ([]platform.Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.connections[tenantID]), nil
}

func (m *Memory) DeleteConnection(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	xs := m.connections[tenantID]
	out := make([]platform.Connection, 0, len(xs))
	for _, c := range xs {
		if c.ID != id {
			out = append(out, c)
		}
	}
	m.connections[tenantID] = out
	return nil
}

func (m *Memory) PutAsset(_ context.Context, a platform.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets[a.TenantID] = upsertByID(m.assets[a.TenantID], a, func(x platform.Asset) string { return x.ID })
	return nil
}

func (m *Memory) ListAssets(_ context.Context, tenantID string) ([]platform.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.assets[tenantID]), nil
}

func (m *Memory) PutEngagement(_ context.Context, e platform.Engagement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.engagements[e.TenantID] = upsertByID(m.engagements[e.TenantID], e, func(x platform.Engagement) string { return x.ID })
	return nil
}

func (m *Memory) ListEngagements(_ context.Context, tenantID string) ([]platform.Engagement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.engagements[tenantID]), nil
}

func (m *Memory) PutFinding(_ context.Context, tenantID string, f types.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings[tenantID] = upsertByID(m.findings[tenantID], f, func(x types.Finding) string { return x.ID })
	return nil
}

func (m *Memory) ListFindings(_ context.Context, tenantID string, filter FindingFilter) ([]types.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []types.Finding
	for _, f := range m.findings[tenantID] {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && string(f.VerificationStatus) != filter.Status {
			continue
		}
		// AssetID filter is best-effort: engine findings don't carry it yet, so an
		// AssetID filter with no match returns nothing rather than silently ignoring.
		if filter.AssetID != "" {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (m *Memory) PutAction(_ context.Context, a platform.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.actions[a.TenantID] == nil {
		m.actions[a.TenantID] = map[string]platform.Action{}
	}
	m.actions[a.TenantID][a.ID] = a
	return nil
}

func (m *Memory) GetAction(_ context.Context, tenantID, id string) (platform.Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.actions[tenantID][id]
	if !ok {
		return platform.Action{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) PendingApprovals(_ context.Context, tenantID string) ([]platform.Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.Action
	for _, a := range m.actions[tenantID] {
		if a.Status == platform.ActPendingApproval {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Memory) ListActions(_ context.Context, tenantID string) ([]platform.Action, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.Action
	for _, a := range m.actions[tenantID] {
		out = append(out, a)
	}
	return out, nil
}

func (m *Memory) UpsertControlState(_ context.Context, cs platform.ControlState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.controls[cs.TenantID] == nil {
		m.controls[cs.TenantID] = map[string]platform.ControlState{}
	}
	m.controls[cs.TenantID][cs.Framework+"/"+cs.ControlID] = cs
	return nil
}

func (m *Memory) Posture(_ context.Context, tenantID, framework string) ([]platform.ControlState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []platform.ControlState
	for _, cs := range m.controls[tenantID] {
		if cs.Framework == framework {
			out = append(out, cs)
		}
	}
	return out, nil
}

func (m *Memory) PutIncident(_ context.Context, i platform.Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.incidents[i.TenantID] == nil {
		m.incidents[i.TenantID] = map[string]platform.Incident{}
	}
	m.incidents[i.TenantID][i.ID] = i
	return nil
}

func (m *Memory) ListIncidents(_ context.Context, tenantID string) ([]platform.Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.Incident, 0, len(m.incidents[tenantID]))
	for _, i := range m.incidents[tenantID] {
		out = append(out, i)
	}
	return out, nil
}

func (m *Memory) PutRisk(_ context.Context, r platform.Risk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.risks[r.TenantID] == nil {
		m.risks[r.TenantID] = map[string]platform.Risk{}
	}
	m.risks[r.TenantID][r.ID] = r
	return nil
}

func (m *Memory) ListRisks(_ context.Context, tenantID string) ([]platform.Risk, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.Risk, 0, len(m.risks[tenantID]))
	for _, r := range m.risks[tenantID] {
		out = append(out, r)
	}
	return out, nil
}

func (m *Memory) PutAIAnalysis(_ context.Context, a platform.AIAnalysis) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aiAnalyses[a.TenantID] == nil {
		m.aiAnalyses[a.TenantID] = map[string]platform.AIAnalysis{}
	}
	m.aiAnalyses[a.TenantID][a.ID] = a
	return nil
}

func (m *Memory) ListAIAnalyses(_ context.Context, tenantID string) ([]platform.AIAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.AIAnalysis, 0, len(m.aiAnalyses[tenantID]))
	for _, a := range m.aiAnalyses[tenantID] {
		out = append(out, a)
	}
	return out, nil
}

func (m *Memory) PutAuditEngagement(_ context.Context, e platform.AuditEngagement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.audits[e.TenantID] == nil {
		m.audits[e.TenantID] = map[string]platform.AuditEngagement{}
	}
	m.audits[e.TenantID][e.ID] = e
	return nil
}

func (m *Memory) ListAuditEngagements(_ context.Context, tenantID string) ([]platform.AuditEngagement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.AuditEngagement, 0, len(m.audits[tenantID]))
	for _, e := range m.audits[tenantID] {
		out = append(out, e)
	}
	return out, nil
}

func (m *Memory) PutPolicy(_ context.Context, p platform.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policies[p.TenantID] == nil {
		m.policies[p.TenantID] = map[string]platform.Policy{}
	}
	m.policies[p.TenantID][p.ID] = p
	return nil
}

func (m *Memory) ListPolicies(_ context.Context, tenantID string) ([]platform.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.Policy, 0, len(m.policies[tenantID]))
	for _, p := range m.policies[tenantID] {
		out = append(out, p)
	}
	return out, nil
}

func (m *Memory) PutIgnoreRule(_ context.Context, ir platform.IgnoreRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ignores[ir.TenantID] == nil {
		m.ignores[ir.TenantID] = map[string]platform.IgnoreRule{}
	}
	m.ignores[ir.TenantID][ir.IssueKey] = ir
	return nil
}

func (m *Memory) ListIgnoreRules(_ context.Context, tenantID string) ([]platform.IgnoreRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.IgnoreRule, 0, len(m.ignores[tenantID]))
	for _, ir := range m.ignores[tenantID] {
		out = append(out, ir)
	}
	return out, nil
}

func (m *Memory) DeleteIgnoreRule(_ context.Context, tenantID, issueKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ignores[tenantID], issueKey)
	return nil
}

func (m *Memory) PutExclusionRule(_ context.Context, er platform.ExclusionRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exclusions[er.TenantID] == nil {
		m.exclusions[er.TenantID] = map[string]platform.ExclusionRule{}
	}
	m.exclusions[er.TenantID][er.ID] = er
	return nil
}

func (m *Memory) ListExclusionRules(_ context.Context, tenantID string) ([]platform.ExclusionRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.ExclusionRule, 0, len(m.exclusions[tenantID]))
	for _, er := range m.exclusions[tenantID] {
		out = append(out, er)
	}
	return out, nil
}

func (m *Memory) DeleteExclusionRule(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.exclusions[tenantID], id)
	return nil
}

func (m *Memory) PutRuntimeEvent(_ context.Context, ev platform.RuntimeEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runtimeEvts[ev.TenantID] = append(m.runtimeEvts[ev.TenantID], ev)
	return nil
}

func (m *Memory) ListRuntimeEvents(_ context.Context, tenantID string) ([]platform.RuntimeEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]platform.RuntimeEvent(nil), m.runtimeEvts[tenantID]...), nil
}

func (m *Memory) PutPentest(_ context.Context, eng pentest.Engagement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pentests[eng.TenantID] == nil {
		m.pentests[eng.TenantID] = map[string]pentest.Engagement{}
	}
	m.pentests[eng.TenantID][eng.ID] = eng
	return nil
}

func (m *Memory) ListPentests(_ context.Context, tenantID string) ([]pentest.Engagement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]pentest.Engagement, 0, len(m.pentests[tenantID]))
	for _, e := range m.pentests[tenantID] {
		out = append(out, e)
	}
	return out, nil
}

func (m *Memory) GetPentest(_ context.Context, tenantID, id string) (pentest.Engagement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.pentests[tenantID][id]
	if !ok {
		return pentest.Engagement{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) PutReviewRequest(_ context.Context, r platform.ReviewRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reviews[r.TenantID] == nil {
		m.reviews[r.TenantID] = map[string]platform.ReviewRequest{}
	}
	m.reviews[r.TenantID][r.ID] = r
	return nil
}

func (m *Memory) ListReviewRequests(_ context.Context, tenantID string) ([]platform.ReviewRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]platform.ReviewRequest, 0, len(m.reviews[tenantID]))
	for _, r := range m.reviews[tenantID] {
		out = append(out, r)
	}
	return out, nil
}

// ReplaceThirdPartyApps swaps the tenant's apps for one provider with the freshly-scanned
// set (so apps revoked since the last scan disappear), leaving other providers untouched.
func (m *Memory) ReplaceThirdPartyApps(_ context.Context, tenantID, provider string, apps []platform.ThirdPartyApp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := make([]platform.ThirdPartyApp, 0, len(m.apps[tenantID]))
	for _, a := range m.apps[tenantID] {
		if a.Provider != provider {
			kept = append(kept, a)
		}
	}
	m.apps[tenantID] = append(kept, apps...)
	return nil
}

func (m *Memory) ListThirdPartyApps(_ context.Context, tenantID string) ([]platform.ThirdPartyApp, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clone(m.apps[tenantID]), nil
}

// Snapshot is the serializable form of a Memory store — what the file-backed store
// persists. Fields are exported so encoding/json can round-trip them.
type Snapshot struct {
	Tenants     map[string]platform.Tenant                     `json:"tenants"`
	Connections map[string][]platform.Connection               `json:"connections"`
	Assets      map[string][]platform.Asset                    `json:"assets"`
	Engagements map[string][]platform.Engagement               `json:"engagements"`
	Findings    map[string][]types.Finding                     `json:"findings"`
	Actions     map[string]map[string]platform.Action          `json:"actions"`
	Controls    map[string]map[string]platform.ControlState    `json:"controls"`
	Incidents   map[string]map[string]platform.Incident        `json:"incidents"`
	Risks       map[string]map[string]platform.Risk            `json:"risks,omitempty"`
	AIAnalyses  map[string]map[string]platform.AIAnalysis      `json:"ai_analyses,omitempty"`
	Audits      map[string]map[string]platform.AuditEngagement `json:"audits,omitempty"`
	Policies    map[string]map[string]platform.Policy          `json:"policies,omitempty"`
	Ignores     map[string]map[string]platform.IgnoreRule      `json:"ignores,omitempty"`
	Exclusions  map[string]map[string]platform.ExclusionRule   `json:"exclusions,omitempty"`
	RuntimeEvts map[string][]platform.RuntimeEvent             `json:"runtime_events,omitempty"`
	Pentests    map[string]map[string]pentest.Engagement       `json:"pentests,omitempty"`
	Reviews     map[string]map[string]platform.ReviewRequest   `json:"reviews"`
	Apps        map[string][]platform.ThirdPartyApp            `json:"apps"`
	Users       map[string]platform.User                       `json:"users"`
	Sessions    map[string]platform.Session                    `json:"sessions"`
	Operators   map[string]platform.Operator                   `json:"operators,omitempty"`
	OpSessions  map[string]platform.OperatorSession            `json:"op_sessions,omitempty"`
}

// Export returns a deep-enough copy of the store's data for persistence (taken under
// the read lock).
func (m *Memory) Export() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		Tenants:     m.tenants,
		Connections: m.connections,
		Assets:      m.assets,
		Engagements: m.engagements,
		Findings:    m.findings,
		Actions:     m.actions,
		Controls:    m.controls,
		Incidents:   m.incidents,
		Risks:       m.risks,
		AIAnalyses:  m.aiAnalyses,
		Audits:      m.audits,
		Policies:    m.policies,
		Ignores:     m.ignores,
		Exclusions:  m.exclusions,
		RuntimeEvts: m.runtimeEvts,
		Pentests:    m.pentests,
		Reviews:     m.reviews,
		Apps:        m.apps,
		Users:       m.users,
		Sessions:    m.sessions,
		Operators:   m.operators,
		OpSessions:  m.opSessions,
	}
}

// load replaces the store's data from a snapshot (nil maps become empty).
func (m *Memory) load(s Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants = orEmptyMap(s.Tenants)
	m.connections = orEmpty(s.Connections)
	m.assets = orEmpty(s.Assets)
	m.engagements = orEmpty(s.Engagements)
	m.findings = orEmpty(s.Findings)
	m.actions = orEmptyNested(s.Actions)
	m.controls = orEmptyControls(s.Controls)
	m.incidents = orEmptyIncidents(s.Incidents)
	m.risks = orEmptyRisks(s.Risks)
	m.aiAnalyses = orEmptyAIAnalyses(s.AIAnalyses)
	m.audits = orEmptyAudits(s.Audits)
	m.policies = orEmptyPolicies(s.Policies)
	m.ignores = orEmptyIgnores(s.Ignores)
	m.exclusions = orEmptyExclusions(s.Exclusions)
	m.runtimeEvts = orEmpty(s.RuntimeEvts)
	m.pentests = orEmptyPentests(s.Pentests)
	m.reviews = orEmptyReviews(s.Reviews)
	m.apps = orEmpty(s.Apps)
	m.users = s.Users
	if m.users == nil {
		m.users = map[string]platform.User{}
	}
	m.sessions = s.Sessions
	if m.sessions == nil {
		m.sessions = map[string]platform.Session{}
	}
	m.operators = s.Operators
	if m.operators == nil {
		m.operators = map[string]platform.Operator{}
	}
	m.opSessions = s.OpSessions
	if m.opSessions == nil {
		m.opSessions = map[string]platform.OperatorSession{}
	}
}

func orEmptyMap(m map[string]platform.Tenant) map[string]platform.Tenant {
	if m == nil {
		return map[string]platform.Tenant{}
	}
	return m
}
func orEmpty[V any](m map[string][]V) map[string][]V {
	if m == nil {
		return map[string][]V{}
	}
	return m
}
func orEmptyNested(m map[string]map[string]platform.Action) map[string]map[string]platform.Action {
	if m == nil {
		return map[string]map[string]platform.Action{}
	}
	return m
}
func orEmptyControls(m map[string]map[string]platform.ControlState) map[string]map[string]platform.ControlState {
	if m == nil {
		return map[string]map[string]platform.ControlState{}
	}
	return m
}
func orEmptyIncidents(m map[string]map[string]platform.Incident) map[string]map[string]platform.Incident {
	if m == nil {
		return map[string]map[string]platform.Incident{}
	}
	return m
}
func orEmptyExclusions(m map[string]map[string]platform.ExclusionRule) map[string]map[string]platform.ExclusionRule {
	if m == nil {
		return map[string]map[string]platform.ExclusionRule{}
	}
	return m
}
func orEmptyIgnores(m map[string]map[string]platform.IgnoreRule) map[string]map[string]platform.IgnoreRule {
	if m == nil {
		return map[string]map[string]platform.IgnoreRule{}
	}
	return m
}
func orEmptyRisks(m map[string]map[string]platform.Risk) map[string]map[string]platform.Risk {
	if m == nil {
		return map[string]map[string]platform.Risk{}
	}
	return m
}
func orEmptyAIAnalyses(m map[string]map[string]platform.AIAnalysis) map[string]map[string]platform.AIAnalysis {
	if m == nil {
		return map[string]map[string]platform.AIAnalysis{}
	}
	return m
}
func orEmptyAudits(m map[string]map[string]platform.AuditEngagement) map[string]map[string]platform.AuditEngagement {
	if m == nil {
		return map[string]map[string]platform.AuditEngagement{}
	}
	return m
}
func orEmptyPolicies(m map[string]map[string]platform.Policy) map[string]map[string]platform.Policy {
	if m == nil {
		return map[string]map[string]platform.Policy{}
	}
	return m
}
func orEmptyPentests(m map[string]map[string]pentest.Engagement) map[string]map[string]pentest.Engagement {
	if m == nil {
		return map[string]map[string]pentest.Engagement{}
	}
	return m
}
func orEmptyReviews(m map[string]map[string]platform.ReviewRequest) map[string]map[string]platform.ReviewRequest {
	if m == nil {
		return map[string]map[string]platform.ReviewRequest{}
	}
	return m
}

// upsertByID replaces an element with the same id, or appends it.
func upsertByID[T any](xs []T, v T, id func(T) string) []T {
	for i := range xs {
		if id(xs[i]) == id(v) {
			xs[i] = v
			return xs
		}
	}
	return append(xs, v)
}

func clone[T any](xs []T) []T {
	if xs == nil {
		return nil
	}
	out := make([]T, len(xs))
	copy(out, xs)
	return out
}
