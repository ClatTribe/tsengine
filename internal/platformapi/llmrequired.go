package platformapi

import "log/slog"

// llmrequired.go: what we say when someone asks for AI work and no model is configured.
//
// Seven handlers had grown their own copy of this message, and every copy told the customer:
//
//	"… configure one in Settings → LLM, or set LLM_API_KEY / LLM_BASE_URL=http://localhost:11434/v1
//	 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"
//
// Three things wrong with that, in increasing order of seriousness.
//
// It is aimed at the wrong person. A founder who clicked "Investigate" is being handed Ollama
// configuration. The one action available to them — Settings → LLM — is buried mid-sentence between
// two environment variables they cannot set.
//
// The copies had drifted (LLM_API_KEY in six, ANTHROPIC_API_KEY in the seventh), which is what
// duplicated prose does.
//
// And the ending is FALSE for the path the customer can take. A key added in Settings resolves per
// request and works immediately; "then restart the platform" describes only the operator's env-var
// path, and tells a customer who just did the right thing that they must now do something they cannot
// do and that would not help.
//
// The operator detail is real and still needed by self-hosters, so it is not deleted — it is logged,
// where an operator will see it and a customer will not.

// llmRequired is the customer-facing message for an AI action that cannot run without a model.
//
// capability names what they were trying to do, in their words ("Cloud investigation"), so the message
// reads as an explanation of that click rather than a generic failure.
func llmRequired(capability string) string {
	return capability + " needs the AI Security Engineer, which is not switched on for this workspace. " +
		"Add your own LLM key under Settings → LLM and it takes effect immediately, or move to a plan that " +
		"includes AI. Scanning, correlation and compliance mapping keep running either way."
}

// logLLMMissing records the operator-facing half: the env vars a self-hosted deployment can set. This
// is the same information the old error carried, moved to the audience that can act on it.
func logLLMMissing(capability string) {
	slog.Info("[llm] an AI capability was requested with no model configured",
		"capability", capability,
		"operator_hint", "set LLM_API_KEY (or ANTHROPIC_API_KEY), or LLM_BASE_URL=http://localhost:11434/v1 "+
			"with LLM_MODEL=<model> for a local Ollama, then restart the platform; a per-tenant key set in "+
			"Settings → LLM needs no restart")
}

// llmRequiredBody is the whole response: the message plus a machine-readable code, so a client can
// route to the settings screen instead of pattern-matching on prose.
func llmRequiredBody(capability string) map[string]string {
	logLLMMissing(capability)
	return errCode(llmRequired(capability), "llm_required")
}
