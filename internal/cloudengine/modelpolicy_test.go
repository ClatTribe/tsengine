package cloudengine

import (
	"os"
	"testing"
)

func TestTierModel_EnvParsing(t *testing.T) {
	t.Setenv("TSENGINE_MODEL_BREADTH", "deepseek-v4")
	if got := TierModel(TierBreadth); got != "deepseek-v4" {
		t.Errorf("breadth override = %q", got)
	}
	t.Setenv("TSENGINE_MODEL_VERIFY", "")
	if got := TierModel(TierVerify); got != "" {
		t.Errorf("unset verify must be empty, got %q", got)
	}
	if got := TierModel(Tier("nonsense")); got != "" {
		t.Errorf("unknown tier must be empty, got %q", got)
	}
	os.Unsetenv("TSENGINE_MODEL_BREADTH")
}

func TestLLMTiered_RebindsModelOnOverride(t *testing.T) {
	base := NewOpenAICompat("key", "gpt-4o-mini", "http://127.0.0.1:1/v1")
	got := LLMTiered(base, TierBreadth)
	if gm, ok := got.(ModelNamer); !ok {
		t.Fatalf("client does not implement ModelNamer: %T", got)
	} else if gm.ModelName() != "gpt-4o-mini" {
		t.Fatalf("no override → same model id expected, got %q", gm.ModelName())
	}
	t.Setenv("TSENGINE_MODEL_BREADTH", "deepseek-v4")
	got2 := LLMTiered(base, TierBreadth)
	if gm, ok := got2.(ModelNamer); !ok || gm.ModelName() != "deepseek-v4" {
		t.Fatalf("override must rebind the model id, got %T/%v", got2, got2)
	}
}
