package webagent

import "strings"

// toolselect.go is the offensive agent's PROGRESSIVE TOOL DISCLOSURE (best-in-class harness engineering):
// the LLM is shown a MINIMAL, task-relevant tool set per turn — not the full 24-tool catalog — so its
// tool-use accuracy stays high (the ≤12-tool concern, CLAUDE.md §2.6, applied to the offensive agent).
//
// Which tools unlock is driven by the WORLD-MODEL state (ADR 0016): early engagement shows recon; once
// there's real surface, the differential probes; credential/hash evidence unlocks the cracking + lateral
// tools; a recorded finding unlocks confirm. This is "load tools only when needed" grounded in what the
// engagement has actually discovered — not a static list.
//
// SAFETY: this narrows only what the LLM SEES; the dispatch table (web.go) keeps every tool, so a tool
// called out-of-phase still works — disclosure is an accuracy optimization, never a capability gate.

// toolGroup maps each tool to its disclosure group. A tool with no entry (should not happen) defaults to
// always-shown, a safe fallback.
var toolGroup = map[string]string{
	// core — the always-present spine (see the model, act, record, end)
	"list_routes": "core", "send_request": "core", "record_finding": "core",
	"note_defense": "core", "finish": "core",
	// recon — find hidden surface (shown while the surface is still thin)
	"discover_content": "recon", "graphql_introspect": "recon",
	// probe — the FP-free differential class-provers + the OSS gateway (shown once there's surface to attack)
	"sqli_bool_probe": "probe", "nosqli_probe": "probe", "bola_probe": "probe",
	"session_idor_probe": "probe", "privesc_probe": "probe", "tamper_probe": "probe",
	"race_probe": "probe", "cors_probe": "probe", "dispatch_oss": "probe",
	// blind — out-of-band + browser (blind/DOM classes; shown with the probes)
	"oob_url": "blind", "oob_check": "blind", "browser_render": "blind",
	// cred — crack/forge (shown when a credential/hash/token appears in evidence)
	"jwt_crack": "cred", "crack_hash": "cred", "try_default_creds": "cred",
	// lateral — the leaked-cred SSH hop (shown alongside cred signals)
	"ssh_exec": "lateral",
	// confirm — re-fire an exploit for the evidence bundle (shown once a finding is recorded)
	"confirm_exploit": "confirm",
}

// reconSurfaceThreshold: below this many known endpoints the surface is "thin" and recon stays visible.
const reconSurfaceThreshold = 8

// selectTools returns the MINIMAL tool subset to show the LLM this turn, chosen from the engagement's
// world-model + evidence state. Deterministic given the Context.
func selectTools(cc *Context) []toolDef {
	active := map[string]bool{"core": true}

	w := BuildWorldModel(cc.History, cc.Findings)
	nEndpoints := len(w.Endpoints)
	hasParams := false
	for _, e := range w.Endpoints {
		if len(e.Params) > 0 {
			hasParams = true
			break
		}
	}

	// recon while the surface is still thin (or nothing has params to attack yet).
	if nEndpoints < reconSurfaceThreshold || !hasParams {
		active["recon"] = true
	}
	// once there IS surface, the differential probes + blind/OOB channels come online.
	if nEndpoints > 0 {
		active["probe"] = true
		active["blind"] = true
	}
	// credential/hash/token evidence unlocks the cracking + lateral-movement tools.
	if credSignal(cc) {
		active["cred"] = true
		active["lateral"] = true
	}
	// a recorded finding unlocks confirm (re-fire for the evidence bundle).
	if len(cc.Findings) > 0 {
		active["confirm"] = true
	}

	out := make([]toolDef, 0, len(tools()))
	for _, t := range tools() {
		g := toolGroup[t.name]
		if g == "" || active[g] {
			out = append(out, t)
		}
	}
	return out
}

// credSignal reports whether the engagement's evidence has surfaced a credential / hash / key / token —
// the trigger to unlock the crack/forge + SSH-lateral tools. Heuristic (it only UNLOCKS a tool, never
// grounds a finding), scanning response snippets + set-cookies for the tell-tale shapes.
func credSignal(cc *Context) bool {
	for _, t := range cc.History {
		hay := t.RespSnippet + " " + strings.Join(t.SetCookies, " ")
		lo := strings.ToLower(hay)
		if strings.Contains(hay, "eyJ") || // a JWT
			strings.Contains(hay, "PRIVATE KEY") || // a leaked private key
			strings.Contains(lo, "password") ||
			strings.Contains(lo, "id_rsa") ||
			hasHexHash(hay) {
			return true
		}
	}
	return false
}

// hasHexHash reports whether s contains a standalone MD5/SHA1/SHA256-length hex string (a dumped hash).
func hasHexHash(s string) bool {
	run := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isHexByte(s[i]) {
			run++
			continue
		}
		if run == 32 || run == 40 || run == 64 {
			return true
		}
		run = 0
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
