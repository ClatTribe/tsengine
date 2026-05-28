// Package dashboard contains the renderer + canonicalizer + attestation
// for vulnerabilities.json — the L1 webappsec handoff contract
// (CLAUDE.md §6).
package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Canonical produces a deterministic JSON encoding of a Scan suitable
// for hashing or signing. Guarantees:
//
//   - JSON object keys appear in lexicographic order at every level
//   - No insignificant whitespace
//   - findings_raw and findings_enriched are sorted by ID
//   - anchors_fired and registry_fired are sorted alphabetically
//   - The Attestation block is stripped (Canonical produces the INPUT to
//     attestation; including it would be circular)
//   - NaN / Inf floats fail loudly rather than emit invalid JSON
//
// Two calls to Canonical on Scans that differ only in slice ordering of
// findings/anchors MUST produce byte-identical output. This is the
// load-bearing invariant for reproducibility (CLAUDE.md §10).
func Canonical(scan types.Scan) ([]byte, error) {
	normalized := normalize(scan)
	return canonicalMarshal(normalized)
}

// normalize returns a Scan with deterministically-ordered slices and no
// Attestation block.
func normalize(scan types.Scan) types.Scan {
	out := scan
	out.Attestation = nil

	out.FindingsRaw = sortFindings(scan.FindingsRaw)
	out.FindingsEnriched = sortFindings(scan.FindingsEnriched)

	out.AnchorsFired = sortedCopy(scan.AnchorsFired)
	out.RegistryFired = sortedCopy(scan.RegistryFired)

	return out
}

func sortFindings(in []types.Finding) []types.Finding {
	if in == nil {
		return nil
	}
	out := make([]types.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// canonicalMarshal produces canonical JSON: sorted object keys, no
// whitespace. The strategy is to marshal once with the standard encoder
// (to get correct escaping/RFC3339 timestamps/etc.), then re-walk via
// generic interface{} to enforce key ordering.
func canonicalMarshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: initial marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: re-decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		// Inspect for finite-ness when it's a float
		if f, err := x.Float64(); err == nil {
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return fmt.Errorf("non-finite number %s", x.String())
			}
		}
		buf.WriteString(x.String())
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical type %T", v)
	}
	return nil
}
