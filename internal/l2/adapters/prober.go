package adapters

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// Prober adapts the tool-replay API (internal/replay) to the L2
// dispatch_l2_probe tool. Per §9, dispatch_l2_probe is "a thin wrapper over
// /replay": depth via a deterministic re-fire of an L1/registry tool, pinned
// to the original scan's corpus + image digest — NOT raw shell (strix's
// `terminal`). The Lead gets depth without arbitrary code execution.
type Prober struct {
	ScanID  string
	RunsDir string
	Spawner replay.Spawner
}

var _ l2.Prober = (*Prober)(nil)

// NewProber wires the prober to a scan: scanID + runsDir locate the original
// scan (for the reproducibility pin), spawner produces the sandbox.
func NewProber(scanID, runsDir string, spawner replay.Spawner) *Prober {
	return &Prober{ScanID: scanID, RunsDir: runsDir, Spawner: spawner}
}

// Probe implements l2.Prober. It maps the LLM's free-form args onto a
// replay.Request (pulling "target" out as the override), re-fires the tool
// via /replay, and renders the resulting findings into a compact summary the
// Lead can cite via update_finding(verified_by="dispatch_l2_probe:<tool>").
func (p *Prober) Probe(ctx context.Context, toolName string, args map[string]any) (string, error) {
	req := replay.Request{ScanID: p.ScanID, Tool: toolName, Args: tool.Args{}}
	for k, v := range args {
		if k == "target" {
			if s, ok := v.(string); ok {
				req.Target = s
				continue
			}
		}
		req.Args[k] = v
	}
	resp, err := replay.Replay(ctx, req, p.RunsDir, p.Spawner)
	if err != nil {
		return "", err
	}
	return renderProbe(toolName, resp), nil
}

func renderProbe(toolName string, resp *replay.Response) string {
	if len(resp.Findings) == 0 {
		return fmt.Sprintf("%s replay (%s): no findings", toolName, resp.ReplayID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s replay (%s): %d finding(s)", toolName, resp.ReplayID, len(resp.Findings))
	for i, f := range resp.Findings {
		if i >= 10 {
			fmt.Fprintf(&b, "\n  …+%d more", len(resp.Findings)-10)
			break
		}
		fmt.Fprintf(&b, "\n  [%s] %s", f.Severity, f.Title)
		if f.Endpoint != "" {
			fmt.Fprintf(&b, " — %s", f.Endpoint)
		}
	}
	return b.String()
}
