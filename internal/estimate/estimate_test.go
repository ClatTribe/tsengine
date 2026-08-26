package estimate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

func TestQuote_RefusesWithoutSignals(t *testing.T) {
	q, missing, ok := Quote(DepthStandard, "gpt-4o", Signals{})
	if ok {
		t.Fatal("a quote with zero size signals must be refused, not invented")
	}
	if len(missing) == 0 || !strings.Contains(missing[0], "files") {
		t.Errorf("the refusal must name the missing signal: %v", missing)
	}
	if q.CostUSD != 0 {
		t.Errorf("a refused quote must be zero-valued, got %+v", q)
	}
}

func TestQuote_FastDepthIsZeroModelSpend(t *testing.T) {
	q, _, ok := Quote(DepthFast, "gpt-4o", Signals{Files: 500})
	if !ok || q.CostUSD != 0 {
		t.Fatalf("fast = anchors only → $0 model cost, got %+v ok=%v", q, ok)
	}
	if !strings.Contains(strings.Join(q.Basis, " "), "no model spend") {
		t.Errorf("the basis must say why it is zero: %v", q.Basis)
	}
}

func TestQuote_ScalesWithFilesAndCapsByDepth(t *testing.T) {
	std, _, _ := Quote(DepthStandard, "gpt-4o-mini", Signals{Files: 5000})
	deep, _, _ := Quote(DepthDeep, "gpt-4o-mini", Signals{Files: 5000})
	// 5000 files → 100 questions raw; standard caps at 12, deep at 25.
	if !strings.Contains(strings.Join(std.Basis, ";"), "cap 12") {
		t.Errorf("standard basis must show the cap: %v", std.Basis)
	}
	if deep.CostUSD <= std.CostUSD {
		t.Errorf("deep must price above standard: deep=%v std=%v", deep.CostUSD, std.CostUSD)
	}
	if strings.Contains(strings.Join(std.Basis, ";"), "unknown") == false && cloudengine.EstimateCost("gpt-4o-mini", cloudengine.Usage{InputTokens: 1}) <= 0 {
		t.Error("pricing book returned non-positive for a known model")
	}
}

func TestQuote_UnknownModelStillQuotes(t *testing.T) {
	q, _, ok := Quote(DepthDeep, "totally-unknown-model", Signals{URLs: 40})
	if !ok || q.CostUSD <= 0 {
		t.Fatalf("an unknown model quotes at default rates (disclosed), got ok=%v cost=%v", ok, q.CostUSD)
	}
}
