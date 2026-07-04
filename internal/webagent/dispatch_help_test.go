package webagent

import (
	"strings"
	"testing"
)

// dispatchOSSHelpText pulls the live dispatch_oss tool help the LLM actually sees.
func dispatchOSSHelpText(t *testing.T) string {
	t.Helper()
	for _, td := range tools() {
		if td.name == "dispatch_oss" {
			return td.help
		}
	}
	t.Fatal("dispatch_oss tool not registered in tools()")
	return ""
}

// TestDispatchOSSHelp_NamesEverySpecialist: every tool in ossSpecialists must be named in the
// dispatch_oss help — else the agent never learns it's dispatchable. The hand-written summary omitted
// padbuster entirely (present in the registry + error lists, absent from the one help the LLM reads),
// so the crypto/padding-oracle specialist was effectively invisible.
func TestDispatchOSSHelp_NamesEverySpecialist(t *testing.T) {
	help := dispatchOSSHelpText(t)
	for name := range ossSpecialists {
		if !strings.Contains(help, name) {
			t.Errorf("dispatch_oss help omits specialist %q — the agent can't discover it", name)
		}
	}
}

// TestDispatchOSSHelp_DocumentsHydraServiceArg: hydra REQUIRES a `service` arg (ssh/ftp/mysql/…); the
// wrapper errors "unsupported/empty service" without it. The help must document it, or an LLM that
// reaches for dispatch_oss(hydra, {"target":"host"}) — the natural call given the old help — silently
// dead-ends (the exact #809 missing-required-arg-guidance class).
func TestDispatchOSSHelp_DocumentsHydraServiceArg(t *testing.T) {
	help := dispatchOSSHelpText(t)
	if !strings.Contains(help, "service") {
		t.Error("dispatch_oss help does not document hydra's required `service` arg — dispatch_oss(hydra,{target}) will silently fail")
	}
}
