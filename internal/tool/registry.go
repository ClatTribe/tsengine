package tool

import (
	"fmt"
	"sort"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = map[string]Tool{}
)

// Register adds t to the global tool registry. Intended to be called
// from package init() in each wrapper package so importing the wrapper
// is enough to make it dispatchable.
//
// Panics on duplicate name. Duplicates are a programmer error — two
// tools claiming the same Name would silently override each other.
func Register(t Tool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := t.Name()
	if name == "" {
		panic("tool.Register: empty Name()")
	}
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("tool.Register: duplicate tool name %q", name))
	}
	registry[name] = t
}

// Get looks up a tool by name. Returns (nil, false) if not registered.
func Get(name string) (Tool, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	t, ok := registry[name]
	return t, ok
}

// All returns every registered tool in deterministic (alphabetical-by-name)
// order. The deterministic order matters for the reproducibility
// invariant (CLAUDE.md §10).
func All() []Tool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Tool, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// reset clears the registry. Test-only.
func reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]Tool{}
}
