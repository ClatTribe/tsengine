package padbuster

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// TestBuildCLI_URLAlias: dispatch_oss(padbuster, {url:...}) must work — "url" is accepted as an
// alias for "target" (the agent passes url= per the dispatch_oss help), same fix as sqlmap.
func TestBuildCLI_URLAlias(t *testing.T) {
	cli, err := buildCLI(tool.Args{"url": "http://t/dec.php", "sample": "AABBCC"})
	if err != nil {
		t.Fatalf("url alias rejected: %v", err)
	}
	if len(cli) < 1 || cli[0] != "http://t/dec.php" {
		t.Fatalf("url not resolved to target: %v", cli)
	}
}
