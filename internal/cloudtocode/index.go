// Package cloudtocode implements "Cloud-to-Code": it links a runtime cloud
// finding (what prowler/CSPM saw in the live account) back to the
// Infrastructure-as-Code resource — file:line — that provisioned it, so a
// developer fixes the misconfiguration at its source instead of patching the
// live resource (which drift would later undo).
//
// The design is two halves:
//
//  1. an IaC INDEX (this file) — a dependency-free Terraform resource-block
//     scanner that walks a source tree and records, per resource, its type,
//     logical name, file:line, and the literal string identifiers present in
//     the block (the physical name attribute, tag values, etc.).
//  2. a MATCHER (match.go) — for each cloud finding, find the IaC resource
//     whose type provisions the finding's service AND that carries an
//     identifier the cloud finding also names. The match is grounded: it only
//     links on a concrete shared token, never a guess.
//
// This is orchestration/correlation glue, not a detection engine — it adds no
// findings, only provenance to existing ones (so CLAUDE.md §13 "no in-house
// detectors" is satisfied).
//
// The scanner is deliberately NOT a full HCL evaluator. It extracts literal
// string tokens that are physically present in the source. An attribute set to
// an interpolation (`bucket = var.name`) yields no token — and correctly
// produces no false link. It degrades honestly: fewer links, never wrong ones.
package cloudtocode

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Resource is one IaC resource block extracted from the source tree.
type Resource struct {
	Type        string   // terraform resource type, e.g. "aws_s3_bucket"
	LogicalName string   // the block's second label, e.g. "assets"
	File        string   // source file, relative to the index root
	Line        int      // 1-based line of the `resource "..." "..." {` header
	Identifiers []string // literal string values found in the block (+ logical name)
}

// Address is the addressable form, e.g. "aws_s3_bucket.assets".
func (r Resource) Address() string { return r.Type + "." + r.LogicalName }

var (
	// resource "TYPE" "NAME" {   — the header that opens a resource block.
	reResourceHeader = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
	// key = "value"  — a literal string assignment (value captured).
	reStringAssign = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"`)
	// "Key" = "value" — a quoted-key assignment, common inside tags { } blocks.
	reQuotedAssign = regexp.MustCompile(`^\s*"[^"]+"\s*=\s*"([^"]*)"`)
)

// IndexDir walks root for Terraform files (*.tf) and returns every resource
// block found. Hidden dirs and the vendored .terraform cache are skipped.
func IndexDir(root string) ([]Resource, error) {
	var out []Resource
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".tf") {
			return nil
		}
		src, rerr := os.ReadFile(path) //nolint:gosec // operator-provided IaC tree
		if rerr != nil {
			return nil // skip unreadable file, don't fail the whole index
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		out = append(out, indexHCL(rel, src)...)
		return nil
	})
	return out, err
}

// indexHCL extracts resource blocks from a single .tf file's bytes. It tracks
// brace depth from the resource header to the matching close, collecting literal
// string identifiers along the way. Exported via IndexBytes for testing.
func indexHCL(file string, src []byte) []Resource {
	var out []Resource
	sc := bufio.NewScanner(strings.NewReader(string(src)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNo := 0
	var cur *Resource
	depth := 0 // brace depth relative to the resource header line

	for sc.Scan() {
		lineNo++
		line := sc.Text()

		if cur == nil {
			if m := reResourceHeader.FindStringSubmatch(line); m != nil {
				cur = &Resource{
					Type:        m[1],
					LogicalName: m[2],
					File:        file,
					Line:        lineNo,
					Identifiers: []string{m[2]}, // the logical name is itself an identifier
				}
				depth = strings.Count(line, "{") - strings.Count(line, "}")
				if depth <= 0 { // single-line block (rare) — close immediately
					out = append(out, *cur)
					cur = nil
				}
			}
			continue
		}

		// Inside a resource block: collect identifiers, track depth.
		if id := identifierFromLine(line); id != "" {
			cur.Identifiers = appendUnique(cur.Identifiers, id)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil { // unterminated block (truncated file) — still record it
		out = append(out, *cur)
	}
	return out
}

// identifierFromLine returns the literal string value of an assignment line, for
// the value half only (the thing that could match a cloud resource name). It
// covers both `name = "x"` and `"Name" = "x"` (tag) shapes.
func identifierFromLine(line string) string {
	if m := reStringAssign.FindStringSubmatch(line); m != nil {
		return strings.TrimSpace(m[2])
	}
	if m := reQuotedAssign.FindStringSubmatch(line); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func appendUnique(xs []string, v string) []string {
	if v == "" {
		return xs
	}
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return xs
		}
	}
	return append(xs, v)
}
