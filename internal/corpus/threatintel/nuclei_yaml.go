package threatintel

import (
	"strconv"
	"strings"
)

// nuclei_yaml.go is the ADR-0019 wiring-PR deliverable: a deliberately MINIMAL YAML-subset
// decoder that turns a nuclei HTTP-template byte-stream into the narrow NucleiTemplateDoc struct
// the pure mapping core (RecordFromNucleiTemplate, exploit_intel.go) already consumes.
//
// Why not a YAML library (ADR 0019's ONE open dependency decision, resolved here): the repo's
// documented convention is dependency-free parsers for small fixed formats — the .tf resource
// indexer, the controlxref matrix reader, the SKILL.md frontmatter parser (internal/detectionskill)
// each hand-parse and say so. Two reasons carry extra weight for THIS input:
//
//  1. nuclei templates are COMMUNITY-AUTHORED (untrusted-ish). Pulling a full YAML engine into the
//     refresh path would widen the attack surface of an untrusted-input parser — the exact trade the
//     frontmatter parser calls out and refuses.
//  2. §10 makes a mis-parse LOW-BLAST-RADIUS by construction: a dropped or malformed ExploitRecord
//     only widens/narrows what the agent TRIES (it is input to the PROPOSE step; the deterministic
//     predicate over the live response still disposes). A parser bug can never manufacture a false
//     positive, so robustness-for-the-common-case beats total-YAML-fidelity here.
//
// Following the convention: anything this decoder does not understand is IGNORED rather than guessed
// at. It targets the structured method/path template shape (the overwhelming majority of CVE
// templates); a `raw:`-request-only template yields no probe and is refused upstream (no skeleton →
// no record), never a half-built one.

// DecodeNucleiTemplate parses a nuclei template YAML body into a NucleiTemplateDoc. ok=false when the
// body is not a recognizable template (no id/http block) — the caller then produces no record.
func DecodeNucleiTemplate(raw []byte) (NucleiTemplateDoc, bool) {
	root := parseYAMLBlock(splitYAMLLines(string(raw)))
	if root == nil || root.m == nil {
		return NucleiTemplateDoc{}, false
	}
	var doc NucleiTemplateDoc
	doc.ID = strings.TrimSpace(root.scalarAt("id"))

	if info := root.child("info"); info != nil {
		doc.Info.Name = strings.TrimSpace(info.scalarAt("name"))
		doc.Info.Severity = strings.ToLower(strings.TrimSpace(info.scalarAt("severity")))
		doc.Info.Tags = tagList(info.at("tags"))
		if cls := info.child("classification"); cls != nil {
			doc.Info.CWE = scalarOrList(cls.at("cwe-id"))
		}
	}

	// nuclei spells the request block "http" (current) or "requests" (legacy); accept either.
	reqSeq := root.at("http")
	if reqSeq == nil {
		reqSeq = root.at("requests")
	}
	if reqSeq != nil {
		for _, item := range reqSeq.seq {
			doc.HTTP = append(doc.HTTP, decodeRequest(item))
		}
	}

	if doc.ID == "" && len(doc.HTTP) == 0 {
		return NucleiTemplateDoc{}, false
	}
	return doc, true
}

// decodeRequest extracts one request block.
func decodeRequest(n *ynode) NucleiRequest {
	if n == nil || n.m == nil {
		return NucleiRequest{}
	}
	req := NucleiRequest{
		Method:            strings.TrimSpace(n.scalarAt("method")),
		Path:              scalarOrList(n.at("path")),
		Body:              n.scalarAt("body"),
		MatchersCondition: strings.ToLower(strings.TrimSpace(n.scalarAt("matchers-condition"))),
	}
	if h := n.child("headers"); h != nil {
		req.Headers = map[string]string{}
		for _, k := range h.keys {
			req.Headers[k] = strings.TrimSpace(h.scalarAt(k))
		}
	}
	if ms := n.at("matchers"); ms != nil {
		for _, m := range ms.seq {
			req.Matchers = append(req.Matchers, decodeMatcher(m))
		}
	}
	return req
}

// decodeMatcher extracts one matcher block.
func decodeMatcher(n *ynode) NucleiMatcher {
	if n == nil || n.m == nil {
		return NucleiMatcher{}
	}
	m := NucleiMatcher{
		Type:     strings.ToLower(strings.TrimSpace(n.scalarAt("type"))),
		Part:     strings.ToLower(strings.TrimSpace(n.scalarAt("part"))),
		Words:    scalarOrList(n.at("words")),
		Regex:    scalarOrList(n.at("regex")),
		DSL:      scalarOrList(n.at("dsl")),
		Negative: parseBool(n.scalarAt("negative")),
	}
	for _, s := range scalarOrList(n.at("status")) {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			m.Status = append(m.Status, v)
		}
	}
	return m
}

// tagList reads nuclei's `tags`, which is USUALLY a comma-separated scalar (`tags: cve,rce,apache`)
// and OCCASIONALLY a list. Both normalize to a trimmed slice.
func tagList(n *ynode) []string {
	if n == nil {
		return nil
	}
	if n.isScalar {
		var out []string
		for _, t := range strings.Split(n.scalar, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	return scalarOrList(n)
}

// scalarOrList normalizes a node that may be a single scalar, a block/flow list, or absent into a
// trimmed string slice. A field nuclei allows in either form (path, cwe-id, words, status) is read
// through this so the shape the template author chose does not change what we extract.
func scalarOrList(n *ynode) []string {
	if n == nil {
		return nil
	}
	if n.isScalar {
		if s := strings.TrimSpace(n.scalar); s != "" {
			return []string{s}
		}
		return nil
	}
	var out []string
	for _, item := range n.seq {
		if item != nil && item.isScalar {
			if s := strings.TrimSpace(item.scalar); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on":
		return true
	}
	return false
}
