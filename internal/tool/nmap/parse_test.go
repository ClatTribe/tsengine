package nmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseXML_OpenPortsOnly(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseXML(blob)
	// 3 open ports on first host (22 ssh, 23 telnet, 6379 redis);
	// 80 closed → skipped; second host is down → skipped.
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3 (only open ports)", len(findings))
	}

	gotEndpoints := map[string]types.Severity{}
	for _, f := range findings {
		gotEndpoints[f.Endpoint] = f.Severity
	}

	// ssh = info, telnet + redis = medium (high-risk services)
	if gotEndpoints["93.184.216.34:22/tcp"] != types.SeverityInfo {
		t.Errorf("ssh should be info; got %q", gotEndpoints["93.184.216.34:22/tcp"])
	}
	if gotEndpoints["93.184.216.34:23/tcp"] != types.SeverityMedium {
		t.Errorf("telnet should be medium; got %q", gotEndpoints["93.184.216.34:23/tcp"])
	}
	if gotEndpoints["93.184.216.34:6379/tcp"] != types.SeverityMedium {
		t.Errorf("redis should be medium; got %q", gotEndpoints["93.184.216.34:6379/tcp"])
	}
}

func TestParseXML_TitleCarriesProductVersion(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseXML(blob)
	var sshFinding *types.SandboxEmittedFinding
	for i := range findings {
		if strings.HasPrefix(findings[i].Endpoint, "93.184.216.34:22") {
			sshFinding = &findings[i]
			break
		}
	}
	if sshFinding == nil {
		t.Fatal("ssh finding missing")
	}
	if !strings.Contains(sshFinding.Title, "OpenSSH") || !strings.Contains(sshFinding.Title, "8.2p1") {
		t.Errorf("title should carry product+version; got %q", sshFinding.Title)
	}
	if sshFinding.ToolArgs["port"] != "22" {
		t.Errorf("ToolArgs port projection lost: %v", sshFinding.ToolArgs)
	}
}

func TestParseXML_EmptyBlob(t *testing.T) {
	if got := parseXML(nil); got != nil {
		t.Errorf("nil expected, got %v", got)
	}
}

func TestParseXML_MalformedXML(t *testing.T) {
	if got := parseXML([]byte("not xml")); got != nil {
		t.Errorf("nil expected for bad xml, got %v", got)
	}
}

func TestNmapTool_Surface(t *testing.T) {
	n := New()
	if n.Name() != "nmap" {
		t.Errorf("Name: %q", n.Name())
	}
	if !n.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
}
