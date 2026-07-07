package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// filterXBOWDefense selects benchmarks by explicit ids (--only) and/or vuln class (--category, matched
// against the first tag). Empty filters → all.
func filterXBOWDefense(in []bench.XBOWBenchmark, only, category string) []bench.XBOWBenchmark {
	ids := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids[strings.ToUpper(id)] = true
		}
	}
	cat := strings.ToLower(strings.TrimSpace(category))
	var out []bench.XBOWBenchmark
	for _, b := range in {
		if len(ids) > 0 && !ids[strings.ToUpper(b.ID)] {
			continue
		}
		if cat != "" {
			if len(b.Config.Tags) == 0 || strings.ToLower(b.Config.Tags[0]) != cat {
				continue
			}
		}
		out = append(out, b)
	}
	return out
}

// copyBenchmarkDir copies a benchmark dir to a fresh temp working copy so a patch never mutates the shared
// suite (the other session builds the same suite). Returns the work dir + a cleanup that removes it.
func copyBenchmarkDir(src string) (string, func(), error) {
	work, err := os.MkdirTemp("", "xbow-def-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	dst := filepath.Join(work, filepath.Base(src))
	if err := copyTree(src, dst); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dst, cleanup, nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "node_modules") {
			return filepath.SkipDir // skip heavy/irrelevant trees (disk)
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // copying a benchmark we control
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

// composeIn finds the docker-compose file in a copied benchmark dir.
func composeIn(dir string) string {
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// targetURL determines the app URL from the published web port (reuses composePort from xbow.go).
func targetURL(ctx context.Context, compose, targetPort string) string {
	if targetPort != "" {
		return "http://localhost:" + targetPort
	}
	if p := composePort(ctx, compose); p != "" {
		return "http://localhost:" + p
	}
	return ""
}

// attackAndRecordExploit obtains a deterministic winning exploit for the challenge. It first tries a CACHED
// exploit (a prior recording) and confirms it still captures on this build (cheap, deterministic); on a
// miss it runs the OFFENSIVE agent to capture the flag + extract the winning request from the transcript,
// then caches it. Returns (exploit, captured, note). captured=false → not_vulnerable (nothing to defend).
func attackAndRecordExploit(ctx context.Context, binary, timeout, target, flag string, b bench.XBOWBenchmark, exploitsDir string) (bench.WinningExploit, bool, string) {
	class := ""
	if len(b.Config.Tags) > 0 {
		class = b.Config.Tags[0]
	}
	// Cached exploit? Confirm it still captures on THIS vuln build (the recorded request is flag-independent).
	if e, ok, _ := bench.LoadExploit(exploitsDir, b.ID); ok && e.Valid() {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		seen, err := bench.ReplayExploit(cctx, httpClient(), target, e, flag)
		cancel()
		if err == nil && seen {
			return e, true, "cached exploit reconfirmed"
		}
	}

	// Run the offensive agent to capture + record. Mirrors gradeInvestigateMode's invocation.
	tmp, err := os.MkdirTemp("", "xbow-def-attack-")
	if err != nil {
		return bench.WinningExploit{}, false, "mktemp: " + err.Error()
	}
	defer os.RemoveAll(tmp)
	scanReport := runReconScan(ctx, binary, target, filepath.Join(tmp, "scan"))
	transcript := filepath.Join(tmp, "transcript.json")
	evidence := filepath.Join(tmp, "evidence.json")
	args := []string{"web-investigate", "--target", target, "--transcript", transcript,
		"--export-evidence", evidence, "--max-requests", "150", "--max-iters", "40"}
	if scanReport != "" {
		args = append(args, "--scan", scanReport)
	}
	if img := os.Getenv("TSENGINE_SANDBOX_IMAGE"); strings.TrimSpace(img) != "" {
		args = append(args, "--oss-sandbox", img)
	}
	actx, cancel := context.WithTimeout(ctx, parseDur(timeout))
	defer cancel()
	cmd := exec.CommandContext(actx, binary, args...)
	cmd.Env = investigateEnv(os.Environ())
	stdout, _ := cmd.CombinedOutput()

	tData, _ := os.ReadFile(transcript) //nolint:gosec // our temp dir
	blob := string(stdout) + "\n" + string(tData)
	if eData, e := os.ReadFile(evidence); e == nil { //nolint:gosec // our temp dir
		blob += "\n" + string(eData)
	}
	if !bench.FlagCaptured(flag, blob) {
		return bench.WinningExploit{}, false, "agent did not capture the flag"
	}
	exploit, ok := bench.ExtractExploitFromTranscript(tData, flag, b.ID, class)
	if !ok {
		// Captured (flag somewhere in the blob) but not in a single replayable turn — e.g. multi-step or
		// OOB. Honest: we can't build a deterministic single-request replay, so we can't defend-verify.
		return bench.WinningExploit{}, false, "flag captured but no single replayable request found (multi-step/OOB — replay unsupported)"
	}
	_ = bench.SaveExploit(exploitsDir, exploit) // best-effort cache
	return exploit, true, "exploit recorded from live capture"
}

// gatherSource collects the app source from a build context for the engineer, bounded so a large app can't
// blow the model context. Skips vendored/heavy trees + binaries; per-file 48KB, total 300KB.
func gatherSource(dir string) []codeagent.SourceFile {
	const perFile = 48 << 10
	const total = 300 << 10
	sourceExt := map[string]bool{
		".php": true, ".py": true, ".js": true, ".ts": true, ".rb": true, ".go": true, ".java": true,
		".html": true, ".htm": true, ".sql": true, ".sh": true, ".pl": true, ".jsp": true, ".ejs": true,
		".conf": true, ".yaml": true, ".yml": true, ".env": true, ".ini": true, ".cfg": true,
	}
	var files []codeagent.SourceFile
	used := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				switch info.Name() {
				case ".git", "node_modules", "vendor", "venv", "__pycache__":
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(info.Name())
		if !sourceExt[ext] && base != "dockerfile" {
			return nil
		}
		if info.Size() > perFile || used+int(info.Size()) > total {
			return nil
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // benchmark source we control
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		files = append(files, codeagent.SourceFile{Path: filepath.ToSlash(rel), Content: string(data)})
		used += len(data)
		return nil
	})
	return files
}

// applyPatch writes the engineer's whole-file replacements into the work dir. Each path is re-checked to be
// inside the work dir (defence-in-depth over codeagent's traversal guard).
func applyPatch(work string, files []codeagent.PatchedFile) error {
	for _, f := range files {
		target := filepath.Join(work, filepath.FromSlash(f.Path))
		clean := filepath.Clean(target)
		if !strings.HasPrefix(clean, filepath.Clean(work)+string(os.PathSeparator)) {
			continue // refuse anything that escaped the work dir
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(clean, []byte(f.Content), 0o644); err != nil { //nolint:gosec // patched app file in a temp copy
			return err
		}
	}
	return nil
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
