package platformapi

import (
	"strings"
	"testing"
)

// What a customer is told when they click an AI action and no model is configured.
//
// The seven handlers that needed this message had each grown their own copy, and every copy ended
// "then restart the platform" — false for the one path the customer can actually take, since a key set
// in Settings resolves per request. They also handed a founder Ollama environment variables.

func TestLLMRequired_TellsTheCustomerWhatTHEYCanDo(t *testing.T) {
	msg := llmRequired("Cloud investigation")
	if !strings.HasPrefix(msg, "Cloud investigation") {
		t.Errorf("the message does not name what they were trying to do: %q", msg)
	}
	if !strings.Contains(msg, "Settings") {
		t.Errorf("the message does not point at the one control they have: %q", msg)
	}
}

// THE ACTUAL BUG: telling a customer to restart the platform. They cannot, and after adding a key in
// Settings they do not need to — it takes effect on the next request.
func TestLLMRequired_DoesNotTellACustomerToRestartTheServer(t *testing.T) {
	msg := llmRequired("AI autofix")
	if strings.Contains(strings.ToLower(msg), "restart") {
		t.Errorf("the customer is told to restart the platform, which is both impossible for them and "+
			"untrue for the Settings path: %q", msg)
	}
}

// Operator configuration is not customer-facing copy. It still exists — it is logged — but it does not
// belong in a founder's error toast.
func TestLLMRequired_CarriesNoOperatorConfiguration(t *testing.T) {
	msg := llmRequired("The compliance advisor")
	for _, leak := range []string{"LLM_API_KEY", "ANTHROPIC_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "ollama", "Ollama", "11434"} {
		if strings.Contains(msg, leak) {
			t.Errorf("%q leaked operator configuration into a customer message: %q", leak, msg)
		}
	}
}

// Deterministic work keeps running, and saying so is the difference between "this feature is off" and
// "the product is broken".
func TestLLMRequired_SaysWhatStillWorks(t *testing.T) {
	msg := llmRequired("Code investigation")
	if !strings.Contains(strings.ToLower(msg), "scanning") {
		t.Errorf("the message does not say the deterministic engine keeps running: %q", msg)
	}
}

// A machine-readable code lets the client route to Settings instead of matching on prose.
func TestLLMRequiredBody_CarriesARoutableCode(t *testing.T) {
	body := llmRequiredBody("AI autofix")
	if body["code"] != "llm_required" {
		t.Errorf("code = %q, want llm_required", body["code"])
	}
	if body["error"] == "" {
		t.Error("no human-readable message alongside the code")
	}
}
