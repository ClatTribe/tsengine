package tenanteval

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AllSources is what internal/uicheck iterates to prove every case source has a customer-facing
// label. That makes it load-bearing in a way its own signature cannot show: a Source constant
// added to the package but not to this list is covered by NOTHING, and the guard downstream goes
// on passing while covering less.
//
// This is the failure the list exists to prevent, one level up — and it is not hypothetical.
// Deleting a member from AllSources was tried against the uicheck guard and the guard stayed
// green, because a shorter list simply asks fewer questions. Derive the truth from the
// declarations instead of trusting the list to be complete.
func TestAllSourcesCoversEveryDeclaredSource(t *testing.T) {
	declared := map[string]bool{}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		f, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Source" {
				return true
			}
			for _, name := range vs.Names {
				declared[name.Name] = true
			}
			return true
		})
	}
	if len(declared) == 0 {
		t.Fatal("no Source constants found — this guard would pass while checking nothing")
	}

	listed := map[string]bool{}
	for _, s := range AllSources() {
		listed[string(s)] = true
	}

	for name := range declared {
		// SourceStarter is deliberately excluded: starter cases are scored under their own arm
		// and never folded into agreement-with-your-experts, so they are not part of this set.
		if name == "SourceStarter" {
			if listed[string(SourceStarter)] {
				t.Errorf("SourceStarter is in AllSources — starter cases are scored under a " +
					"separate arm and must not be mixed into the customer's agreement score")
			}
			continue
		}
		var val string
		switch name {
		case "SourceReinstated":
			val = string(SourceReinstated)
		case "SourceIgnored":
			val = string(SourceIgnored)
		case "SourceConfirmedFix":
			val = string(SourceConfirmedFix)
		case "SourceEvidenceInsufficient":
			val = string(SourceEvidenceInsufficient)
		case "SourceAcceptedRisk":
			val = string(SourceAcceptedRisk)
		case "SourceHumanVerdict":
			val = string(SourceHumanVerdict)
		default:
			t.Errorf("Source constant %s is declared but this guard does not know it — add it to "+
				"AllSources (and to the eval page's SOURCE_LABEL), or record here why it is "+
				"excluded like SourceStarter is. An unlisted source is checked by nothing.", name)
			continue
		}
		if !listed[val] {
			t.Errorf("Source constant %s (%q) is declared but missing from AllSources.\n\n"+
				"internal/uicheck iterates AllSources to prove every source has a customer-facing "+
				"label, so a source missing here is silently exempt from that guard — and renders "+
				"to the customer as its raw enum slug.", name, val)
		}
	}
}
