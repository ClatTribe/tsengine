// Package apkid wraps APKiD (the "PEiD for Android") as a tsengine depth Tool for the mobile asset. It
// fingerprints the COMPILER, PACKER, OBFUSCATOR, and ANTI-ANALYSIS (anti-vm / anti-debug / anti-disassembly)
// techniques present in an APK/DEX — a tampering / repackaging / evasion signal that mobsfscan's SAST and
// gitleaks's secret scan don't cover. A packed or anti-analysis-laden build is a strong "this app may be
// repackaged malware or is hiding something" indicator (and, benignly, commercial protection — so the finding
// states the FACT and leaves the verdict to the human/agent, §10). Registry-tier (on-demand), registered via init().
package apkid

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// APKiD is the tool.Tool implementation.
type APKiD struct{}

// New constructs an APKiD wrapper.
func New() *APKiD { return &APKiD{} }

func (*APKiD) Name() string              { return "apkid" }
func (*APKiD) SandboxExecution() bool    { return true }
func (*APKiD) MITRETechniques() []string { return []string{"T1406", "T1633"} } // obfuscated files; sandbox evasion (ATT&CK Mobile)

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*APKiD) KnownArgs() []string { return []string{"target"} }

// Run fingerprints an APK / DEX bundle. Recognized args:
//
//	"target" string — required, the path to the .apk/.dex (workspace mount).
func (*APKiD) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	target, _ := args["target"].(string)
	if strings.TrimSpace(target) == "" {
		return tool.Result{}, errors.New("apkid: missing required arg 'target'")
	}
	// -j: JSON output. APKiD exits non-zero only on a hard error, not on "found techniques".
	cmd := exec.CommandContext(ctx, "apkid", "-j", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{Output: "apkid: " + err.Error()}, nil
		}
	}
	return tool.Result{Output: string(out), Findings: parse(out)}, nil
}

// report mirrors APKiD's -j JSON: a list of files, each with category→[]matched-technique.
type report struct {
	Files []struct {
		Filename string              `json:"filename"`
		Matches  map[string][]string `json:"matches"`
	} `json:"files"`
}

// categoryMeta maps an APKiD match category to its severity + how to phrase it. "compiler" is purely
// informational (which toolchain built it) so it never becomes a finding. Anti-analysis is suspicious but
// also common in legitimate hardened apps → info; packer/manipulator (repackaging/tampering) → medium.
var categoryMeta = map[string]struct {
	sev  types.Severity
	verb string
}{
	"packer":           {types.SeverityMedium, "is packed with"},
	"manipulator":      {types.SeverityMedium, "shows manipulation by"},
	"obfuscator":       {types.SeverityLow, "is obfuscated by"},
	"anti_vm":          {types.SeverityInfo, "carries anti-VM evasion:"},
	"anti_debug":       {types.SeverityInfo, "carries anti-debug evasion:"},
	"anti_disassembly": {types.SeverityInfo, "carries anti-disassembly evasion:"},
	"abnormal":         {types.SeverityLow, "has abnormal structure:"},
	"dropper":          {types.SeverityMedium, "shows dropper behaviour:"},
}

func parse(blob []byte) []types.SandboxEmittedFinding {
	var r report
	if json.Unmarshal(blob, &r) != nil {
		return nil
	}
	var out []types.SandboxEmittedFinding
	for _, f := range r.Files {
		for cat, techniques := range f.Matches {
			meta, ok := categoryMeta[cat]
			if !ok || len(techniques) == 0 {
				continue // "compiler" and any unknown category → not a finding
			}
			tech := strings.Join(techniques, ", ")
			out = append(out, types.SandboxEmittedFinding{
				RuleID:          "apkid::" + cat,
				Tool:            "apkid",
				Severity:        meta.sev,
				Endpoint:        f.Filename,
				Title:           "APKiD: " + f.Filename + " " + meta.verb + " " + tech,
				Description:     "APKiD fingerprinted " + cat + " technique(s) [" + tech + "] in " + f.Filename + ". This can indicate repackaged malware, tampering, or anti-analysis — or legitimate commercial protection. Verify the build is expected; an unexpected packer/obfuscator on your own app warrants investigation.",
				CWE:             []string{"CWE-656"}, // reliance on security through obscurity / obfuscation
				MITRETechniques: []string{"T1406"},
			})
		}
	}
	return out
}

func init() { tool.Register(New()) }
