package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- test doubles ------------------------------------------------

type mockDispatcher struct {
	expectTool string
	result     tool.Result
	err        error
	gotArgs    tool.Args
}

func (m *mockDispatcher) Execute(_ context.Context, name string, args tool.Args) (tool.Result, error) {
	m.gotArgs = args
	if name != m.expectTool {
		return tool.Result{}, errors.New("unexpected tool: " + name)
	}
	return m.result, m.err
}

type mockSpawner struct {
	disp        Dispatcher
	gotDigest   string
	destroyHits int
}

func (m *mockSpawner) Spawn(_ context.Context, digest string) (Dispatcher, func(context.Context) error, error) {
	m.gotDigest = digest
	return m.disp, func(context.Context) error { m.destroyHits++; return nil }, nil
}

// --- helpers ----------------------------------------------------

func writeScan(t *testing.T, runsDir, scanID string, scan types.Scan) {
	t.Helper()
	dir := filepath.Join(runsDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "vulnerabilities.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(scan); err != nil {
		t.Fatal(err)
	}
}

func freshScan() types.Scan {
	return types.Scan{
		ScanID:    "scan-abc",
		Asset:     types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"},
		StartedAt: time.Now().UTC(),
		Engine:    types.Engine{Version: "0.1.0", SandboxImageDigest: "sha256:deadbeef"},
	}
}

// --- tests -------------------------------------------------------

func TestReplay_HappyPath(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-abc", freshScan())

	disp := &mockDispatcher{
		expectTool: "nuclei",
		result: tool.Result{
			Findings: []types.SandboxEmittedFinding{
				{RuleID: "nuclei::test", Tool: "nuclei", Severity: types.SeverityMedium, Title: "x"},
			},
		},
	}
	sp := &mockSpawner{disp: disp}

	resp, err := Replay(context.Background(), Request{
		ScanID: "scan-abc",
		Tool:   "nuclei",
		Target: "https://example.com/specific",
		Args:   tool.Args{"templates": "cves/"},
	}, dir, sp)

	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if sp.gotDigest != "sha256:deadbeef" {
		t.Errorf("spawner not pinned to original digest: %q", sp.gotDigest)
	}
	if sp.destroyHits != 1 {
		t.Errorf("destroy called %d times; want 1", sp.destroyHits)
	}
	if got := disp.gotArgs["target"]; got != "https://example.com/specific" {
		t.Errorf("target override lost: %v", got)
	}
	if disp.gotArgs["templates"] != "cves/" {
		t.Errorf("extra args lost: %v", disp.gotArgs)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("findings: %d", len(resp.Findings))
	}
	if resp.Findings[0].DiscoveryMethod == nil ||
		resp.Findings[0].DiscoveryMethod.ReplayOf == "" ||
		resp.Findings[0].DiscoveryMethod.Primary != "tool_replay" {
		t.Errorf("DiscoveryMethod not stamped: %+v", resp.Findings[0].DiscoveryMethod)
	}
	if !strings.HasPrefix(resp.Findings[0].ID, "rpl-") {
		t.Errorf("finding ID should embed replay id; got %q", resp.Findings[0].ID)
	}
}

func TestReplay_TargetDefaultsToOriginal(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-abc", freshScan())

	disp := &mockDispatcher{expectTool: "nuclei"}
	sp := &mockSpawner{disp: disp}

	_, err := Replay(context.Background(), Request{
		ScanID: "scan-abc",
		Tool:   "nuclei",
		// no target — use original
	}, dir, sp)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if disp.gotArgs["target"] != "https://example.com" {
		t.Errorf("target default lost: %v", disp.gotArgs)
	}
}

func TestReplay_RejectsMissingScanID(t *testing.T) {
	_, err := Replay(context.Background(), Request{Tool: "nuclei"}, t.TempDir(), &mockSpawner{})
	if err == nil || !errors.Is(err, errBadRequest) {
		t.Errorf("expected bad-request error; got %v", err)
	}
}

// scan_id is a single path element under runsDir — a traversal value must be refused, never joined into
// a path that escapes runsDir to read an arbitrary file.
func TestReplay_RejectsTraversalScanID(t *testing.T) {
	for _, bad := range []string{"../../etc", "..", ".", "a/b", "x/../../y", `a\b`, "foo/vulnerabilities"} {
		_, err := Replay(context.Background(), Request{ScanID: bad, Tool: "nuclei"}, t.TempDir(), &mockSpawner{})
		if err == nil || !errors.Is(err, errBadRequest) {
			t.Errorf("scan_id %q must be rejected as a bad request, got %v", bad, err)
		}
	}
	// a normal uuid-shaped scan_id passes validation (it then fails later as not-found, NOT bad-request).
	_, err := Replay(context.Background(), Request{ScanID: "rpl-1a2b3c4d", Tool: "nuclei"}, t.TempDir(), &mockSpawner{})
	if errors.Is(err, errBadRequest) {
		t.Errorf("a normal scan_id must pass validation, got bad-request: %v", err)
	}
}

func TestReplay_RejectsMissingTool(t *testing.T) {
	_, err := Replay(context.Background(), Request{ScanID: "x"}, t.TempDir(), &mockSpawner{})
	if err == nil || !errors.Is(err, errBadRequest) {
		t.Errorf("expected bad-request error; got %v", err)
	}
}

func TestReplay_RejectsMissingDigest(t *testing.T) {
	dir := t.TempDir()
	scan := freshScan()
	scan.Engine.SandboxImageDigest = ""
	writeScan(t, dir, "scan-abc", scan)

	_, err := Replay(context.Background(), Request{ScanID: "scan-abc", Tool: "nuclei"},
		dir, &mockSpawner{disp: &mockDispatcher{}})
	if err == nil || !strings.Contains(err.Error(), "image_digest") {
		t.Errorf("expected digest error; got %v", err)
	}
}

func TestReplay_ScanNotFound(t *testing.T) {
	_, err := Replay(context.Background(), Request{ScanID: "nope", Tool: "nuclei"},
		t.TempDir(), &mockSpawner{})
	if err == nil || !errors.Is(err, errNotFound) {
		t.Errorf("expected not-found error; got %v", err)
	}
}

func TestHTTPHandler_404OnUnknownScan(t *testing.T) {
	srv := httptest.NewServer(HTTPHandler(t.TempDir(), &mockSpawner{}))
	defer srv.Close()

	body, _ := json.Marshal(Request{ScanID: "nope", Tool: "nuclei"})
	resp, err := http.Post(srv.URL+"/replay", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", resp.StatusCode)
	}
}

func TestHTTPHandler_400OnBadJSON(t *testing.T) {
	srv := httptest.NewServer(HTTPHandler(t.TempDir(), &mockSpawner{}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/replay", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestHTTPHandler_405OnGET(t *testing.T) {
	srv := httptest.NewServer(HTTPHandler(t.TempDir(), &mockSpawner{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/replay")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", resp.StatusCode)
	}
}

func TestHTTPHandler_Success(t *testing.T) {
	dir := t.TempDir()
	writeScan(t, dir, "scan-abc", freshScan())

	sp := &mockSpawner{disp: &mockDispatcher{
		expectTool: "nuclei",
		result: tool.Result{
			Findings: []types.SandboxEmittedFinding{{RuleID: "x", Tool: "nuclei", Severity: types.SeverityInfo, Title: "t"}},
		},
	}}
	srv := httptest.NewServer(HTTPHandler(dir, sp))
	defer srv.Close()

	body, _ := json.Marshal(Request{ScanID: "scan-abc", Tool: "nuclei"})
	resp, err := http.Post(srv.URL+"/replay", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Errorf("findings: got %d, want 1", len(got.Findings))
	}
	if got.ReplayID == "" {
		t.Error("missing replay_id")
	}
}
