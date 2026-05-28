package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CorpusInfo is the sandbox-side report of installed signature/template/
// DB versions. Best-effort — any field the sandbox can't determine is
// omitted. The host folds this into vulnerabilities.json's corpus block
// for reproducibility (CLAUDE.md §10).
type CorpusInfo struct {
	NucleiTemplates string            `json:"nuclei_templates,omitempty"`
	NucleiEngine    string            `json:"nuclei_engine,omitempty"`
	TrivyDBUpdated  string            `json:"trivy_db_updated,omitempty"`
	ToolVersions    map[string]string `json:"tool_versions,omitempty"`
}

func handleCorpus(w http.ResponseWriter, _ *http.Request) {
	info := corpusInfo()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(info)
}

func corpusInfo() CorpusInfo {
	info := CorpusInfo{ToolVersions: map[string]string{}}
	info.NucleiTemplates, info.NucleiEngine = nucleiVersions()
	info.TrivyDBUpdated = trivyDBUpdated()
	for _, tv := range []struct{ tool, flag string }{
		{"nuclei", "-version"},
		{"dalfox", "version"},
		{"subfinder", "-version"},
		{"nmap", "--version"},
		{"trivy", "--version"},
	} {
		if v := cleanVersion(runVersion(tv.tool, tv.flag)); v != "" {
			info.ToolVersions[tv.tool] = v
		}
	}
	return info
}

var (
	ansiRE    = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	versionRE = regexp.MustCompile(`v?\d+\.\d+(\.\d+)?(p\d+)?`)
)

// cleanVersion strips ANSI color codes (nuclei/subfinder colorize their
// banners) and extracts the first semver-ish token. Tools print their
// version amid ASCII-art banners (dalfox) or log-prefixed lines
// (nuclei) — a bare version token is the stable, comparable value.
func cleanVersion(raw string) string {
	s := ansiRE.ReplaceAllString(raw, "")
	if m := versionRE.FindString(s); m != "" {
		return m
	}
	return firstLine(s)
}

// nucleiVersions reads the templates version from nuclei's config file
// and the engine version from `nuclei -version`.
func nucleiVersions() (templates, engine string) {
	// nuclei records the installed templates version in its config dir.
	home, _ := os.UserHomeDir()
	cfg := filepath.Join(home, ".config", "nuclei", ".templates-config.json")
	if data, err := os.ReadFile(cfg); err == nil { //nolint:gosec // fixed path
		var c struct {
			TemplateVersion  string `json:"nuclei-templates-version"`
			TemplateVersion2 string `json:"templates-version"`
		}
		if json.Unmarshal(data, &c) == nil {
			templates = firstNonEmpty(c.TemplateVersion, c.TemplateVersion2)
		}
	}
	// Engine version from the banner line "Nuclei Engine Version: vX".
	out := runVersion("nuclei", "-version")
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "Version:"); i >= 0 {
			engine = strings.TrimSpace(line[i+len("Version:"):])
			break
		}
	}
	return templates, engine
}

// trivyDBUpdated parses `trivy version --format json` for the DB
// UpdatedAt timestamp. Empty if no DB is present yet.
func trivyDBUpdated() string {
	cmd := exec.Command("trivy", "version", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var v struct {
		VulnerabilityDB struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if json.Unmarshal(out, &v) != nil {
		return ""
	}
	if v.VulnerabilityDB.UpdatedAt == "" {
		return ""
	}
	// Normalize to RFC3339 if parseable.
	if t, err := time.Parse(time.RFC3339, v.VulnerabilityDB.UpdatedAt); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return v.VulnerabilityDB.UpdatedAt
}

func runVersion(tool, flag string) string {
	cmd := exec.Command(tool, flag)
	out, _ := cmd.CombinedOutput() // version flags often exit non-zero
	return string(out)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
