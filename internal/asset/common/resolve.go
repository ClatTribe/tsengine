package common

import "github.com/ClatTribe/tsengine/internal/tool"

// ResolveTools is the shared helper every asset Handler uses to look up
// its anchor + registry tools from the global tool.Registry. Names
// that aren't registered (because a wrapper hasn't been imported in
// this build) are silently skipped — that lets a Handler declare its
// intended anchor list even when the tool wrapper hasn't shipped yet.
func ResolveTools(names []string) []tool.Tool {
	out := make([]tool.Tool, 0, len(names))
	for _, n := range names {
		if t, ok := tool.Get(n); ok {
			out = append(out, t)
		}
	}
	return out
}
