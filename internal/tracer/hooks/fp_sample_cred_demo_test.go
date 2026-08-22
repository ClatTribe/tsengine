package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The demo estate must not be staged on a credential this filter classifies as noise.
//
// The seeded cross-surface attack path — the product's flagship capability, and the first thing a
// prospect is shown — used AWS's documented AKIAIOSFODNN7EXAMPLE as its bridge entity: the shared
// identifier that links the web SSRF to the cloud admin role. That is a value listed right here as
// one where "a scanner matching one has matched a document, not a secret", so the demo asserted as
// its headline finding a string the engine exists to suppress. It is also recognisable on sight to
// anyone who has read the AWS docs, which is most of the audience for a cloud attack path.
//
// Checked against the REAL map rather than a copy of it, so adding a sample credential to the
// filter automatically covers the demo too.
func TestDemoSeedUsesNoDocumentedSampleCredential(t *testing.T) {
	seed, err := filepath.Abs(filepath.Join("..", "..", "..", "cmd", "seed-demo", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(seed)
	if err != nil {
		t.Skipf("seed-demo not present: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		// The seed explains in a comment WHY it does not use one; that mention is not a use.
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for value, desc := range publicSampleCredentials {
			if strings.Contains(line, value) {
				t.Errorf("the demo estate uses %s\n\n  %s\n\n"+
					"That is %s — a value this filter demotes because matching it means matching a "+
					"document, not a secret. Staging the demo on it shows a prospect, as a headline "+
					"finding, the exact thing the product is built to suppress. Use a made-up key.",
					value, strings.TrimSpace(line), desc)
			}
		}
	}
}
