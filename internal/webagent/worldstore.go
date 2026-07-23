package webagent

import (
	"context"
	"encoding/json"
	"sync"
)

// worldstore.go is ADR 0016 P5 — optional, platform-gated PERSISTENCE for the world-model. By default the
// model is in-process (rebuilt from evidence each engagement). A WorldStore lets the platform persist it
// per engagement/target so a re-run or a resumed engagement starts from what was already learned (surface,
// held sessions, pivots, blocked endpoints) instead of from zero — the long-horizon "don't re-discover"
// payoff. nil store → today's ephemeral behavior (no blast-radius change).
//
// Secret discipline (§10 / the CapturedSession rule): only the redacted model is persisted — WMIdentity
// carries a fingerprint, never the live token — so nothing sensitive is written to durable storage.

// WorldStore persists a world-model per key (an engagement id or a stable target id).
type WorldStore interface {
	Save(ctx context.Context, key string, w *WorldModel) error
	Load(ctx context.Context, key string) (*WorldModel, bool, error)
}

// MemoryWorldStore is an in-process WorldStore that round-trips through JSON (so it exercises the same
// serialization a durable backend would, and hands back an independent copy). Concurrency-safe.
type MemoryWorldStore struct {
	mu   sync.Mutex
	blob map[string][]byte
}

// NewMemoryWorldStore constructs an empty in-memory store.
func NewMemoryWorldStore() *MemoryWorldStore { return &MemoryWorldStore{blob: map[string][]byte{}} }

func (m *MemoryWorldStore) Save(_ context.Context, key string, w *WorldModel) error {
	if w == nil {
		return nil
	}
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blob == nil {
		m.blob = map[string][]byte{}
	}
	m.blob[key] = b
	return nil
}

func (m *MemoryWorldStore) Load(_ context.Context, key string) (*WorldModel, bool, error) {
	m.mu.Lock()
	b, ok := m.blob[key]
	m.mu.Unlock()
	if !ok {
		return nil, false, nil
	}
	var w WorldModel
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, false, err
	}
	if w.Hosts == nil {
		w.Hosts = map[string]*WMHost{}
	}
	if w.Endpoints == nil {
		w.Endpoints = map[string]*WMEndpoint{}
	}
	return &w, true, nil
}

// Merge folds a PRIOR world-model (e.g. loaded from a store) into w, so a resumed engagement carries
// forward what was learned. Deterministic + union semantics: hosts union their services; endpoints union
// their params + tested outcomes (a "confirmed" in either side wins over "blocked"); identities/attempts
// dedup; pivot edges dedup. Grounding is preserved — every merged entity still carries the evidence turn
// that originally produced it (from the prior engagement).
func (w *WorldModel) Merge(prior *WorldModel) {
	if prior == nil {
		return
	}
	if w.FirstWebHost == "" {
		w.FirstWebHost = prior.FirstWebHost
	}
	for id, ph := range prior.Hosts {
		h := w.Hosts[id]
		if h == nil {
			w.Hosts[id] = ph
			continue
		}
		h.Reachable = h.Reachable || ph.Reachable
		for _, s := range ph.Services {
			h.Services = addUnique(h.Services, s)
		}
	}
	for key, pe := range prior.Endpoints {
		e := w.Endpoints[key]
		if e == nil {
			w.Endpoints[key] = pe
			continue
		}
		for _, p := range pe.Params {
			e.Params = addUnique(e.Params, p)
		}
		e.AuthRequired = e.AuthRequired || pe.AuthRequired
		for c, o := range pe.Tested {
			if e.Tested == nil {
				e.Tested = map[string]string{}
			}
			if e.Tested[c] != "confirmed" { // a confirmed on either side is the stronger outcome
				e.Tested[c] = o
			}
		}
	}
	seenID := map[string]bool{}
	for _, id := range w.Identities {
		seenID[id.Fingerprint] = true
	}
	for _, pid := range prior.Identities {
		if !seenID[pid.Fingerprint] {
			seenID[pid.Fingerprint] = true
			w.Identities = append(w.Identities, pid)
		}
	}
	seenA := map[string]bool{}
	for _, a := range w.Attempts {
		seenA[a.Endpoint+"|"+a.Class+"|"+a.Outcome] = true
	}
	for _, pa := range prior.Attempts {
		k := pa.Endpoint + "|" + pa.Class + "|" + pa.Outcome
		if !seenA[k] {
			seenA[k] = true
			w.Attempts = append(w.Attempts, pa)
		}
	}
	for _, pe := range prior.Edges {
		w.addEdge(pe)
	}
}
