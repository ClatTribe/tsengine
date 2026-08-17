package main

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// dispatch_oss (§12.7) is the offensive agent's single gateway into the sandbox OSS registry. Its
// curated tool set (webagent.OSSSpecialistNames) is a THIRD list, separate from the
// toolsbundle↔imports.go parity the sibling test already guards: a specialist added there but absent
// from the sandbox tool-server passes that parity (both registries lack it consistently) yet 404s the
// moment the agent dispatches it — a silent capability gap discovered only mid-engagement. This closes
// that: every dispatch_oss specialist must actually be registered in the sandbox executor.
func TestOSSSpecialistsAreRegisteredInSandbox(t *testing.T) {
	sandbox := toolImports(t, "imports.go")
	for _, name := range webagent.OSSSpecialistNames() {
		if !sandbox[name] {
			t.Errorf("dispatch_oss offers %q but it is NOT imported in cmd/tool-server/imports.go — the "+
				"agent will dispatch it and get a runtime 404. Register the tool (and add it to "+
				"internal/toolsbundle too, per the host/sandbox parity test).", name)
		}
	}
}
