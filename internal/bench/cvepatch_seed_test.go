package bench

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// Validates the SEED DRIVERS themselves: a correct fix must score FIXED, and the untouched vulnerable
// code must score NOT_FIXED. An oracle that cannot tell those apart measures nothing.
func TestSeedDriversDiscriminate(t *testing.T) {
	cases, err := LoadCVEPatch("../../fixtures/cvepatch/seed.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	gold := map[string]string{
		"seed-path-traversal-node":  "const path = require('path');\nconst fs = require('fs');\n\nconst ROOT = path.join(__dirname, 'templates');\n\nfunction readTemplate(name) {\n  const p = path.resolve(ROOT, name);\n  if (!p.startsWith(ROOT + path.sep)) throw new Error('outside root');\n  return fs.readFileSync(p, 'utf8');\n}\n\nmodule.exports = { readTemplate, ROOT };\n",
		"seed-command-injection-py": "import subprocess\n\n\ndef ping(host):\n    out = subprocess.run(['echo', 'PING', host], capture_output=True, text=True)\n    return out.stdout\n",
		"seed-xss-render-node":      "function esc(s) {\n  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;');\n}\n\nfunction renderGreeting(name) {\n  return '<div class=\"greet\">Hello, ' + esc(name) + '!</div>';\n}\n\nmodule.exports = { renderGreeting };\n",
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			good, ok := gold[c.ID]
			if !ok {
				t.Skip("no gold fix")
			}
			fixed := VerifyPatch(context.Background(), codeagent.Patch{
				Files: []codeagent.PatchedFile{{Path: c.GoldFiles[0], Content: good}},
			}, c.Verify)
			if fixed != JudgeFixed {
				t.Errorf("a CORRECT fix scored %v, want fixed — the driver cannot recognise a real fix", fixed)
			}
			// The unpatched original must NOT pass, or the driver proves nothing.
			orig := VerifyPatch(context.Background(), codeagent.Patch{
				Files: []codeagent.PatchedFile{{Path: c.VulnFiles[0].Path, Content: c.VulnFiles[0].Content}},
			}, c.Verify)
			if orig == JudgeFixed {
				t.Errorf("the VULNERABLE original scored fixed — the driver does not actually exploit")
			}
		})
	}
}
