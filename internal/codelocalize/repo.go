package codelocalize

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// File is one source file the localizer scans. Content is the raw text (localization is language-agnostic
// token matching over source text, so no parser/AST is needed — the Antares approach works across
// Go/JS/TS/Python/Java/PHP source uniformly).
type File struct {
	Path    string // repo-relative, forward-slash normalized
	Content string
}

// Repo is the source surface to localize within — the whole tree for a repository asset, or a subset.
type Repo []File

// sourceExts are the extensions localization scans. Non-source (assets, lockfiles, vendored blobs) are
// skipped so a huge minified/vendored file can't dominate or bloat the scan.
var sourceExts = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".py": true, ".rb": true, ".php": true, ".java": true, ".kt": true, ".scala": true, ".cs": true,
	".c": true, ".cc": true, ".cpp": true, ".h": true, ".hpp": true, ".rs": true, ".swift": true,
}

// skipDirs are trees never worth localizing into (dependencies, VCS, build output).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
	".next": true, "__pycache__": true, ".venv": true, "venv": true, "site-packages": true,
}

// LoadOptions bound a repo load so a pathological tree can't blow up memory/time.
type LoadOptions struct {
	MaxFileBytes int // per-file cap; a file larger than this is skipped (0 → default 512KiB)
	MaxFiles     int // total-file cap; 0 → default 5000
}

func (o LoadOptions) withDefaults() LoadOptions {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 512 * 1024
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = 5000
	}
	return o
}

// LoadRepo walks dir and returns the source Repo, honoring the extension allowlist, skip-dirs, and caps.
// Grounded: it reads only what is really on disk; an unreadable file is skipped, never faked.
func LoadRepo(dir string, opts LoadOptions) (Repo, error) {
	opts = opts.withDefaults()
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", dir, err)
	}
	var repo Repo
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip, never fail the whole walk
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(repo) >= opts.MaxFiles {
			return filepath.SkipAll
		}
		if !sourceExts[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > int64(opts.MaxFileBytes) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			rel = p
		}
		repo = append(repo, File{Path: filepath.ToSlash(rel), Content: string(b)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %q: %w", root, err)
	}
	return repo, nil
}
