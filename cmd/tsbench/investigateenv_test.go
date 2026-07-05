package main

import (
	"strings"
	"testing"
)

// countKey returns how many entries in env set the given KEY= and the last value seen.
func countKey(env []string, key string) (int, string) {
	n, val := 0, ""
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			n++
			val = strings.TrimPrefix(kv, key+"=")
		}
	}
	return n, val
}

// TestInvestigateEnv_SetsOOBHostForDockerizedTargets: XBOW benchmarks are ALL dockerized, so the OOB
// collector (which listens on 0.0.0.0) must advertise host.docker.internal — a host the TARGET CONTAINER
// can reach — NOT 127.0.0.1 (which makes the container call BACK TO ITSELF, so every blind SSRF/XSS/cmdi
// OOB callback silently never fires). Observed live on XBEN-082: oob_url() minted http://127.0.0.1:<port>.
// The harness must inject TSENGINE_OOB_HOST=host.docker.internal into the web-investigate subprocess env.
func TestInvestigateEnv_SetsOOBHostForDockerizedTargets(t *testing.T) {
	env := investigateEnv([]string{"PATH=/usr/bin", "HOME=/root"})
	n, val := countKey(env, "TSENGINE_OOB_HOST")
	if n != 1 {
		t.Fatalf("want exactly one TSENGINE_OOB_HOST entry, got %d in %v", n, env)
	}
	if val != "host.docker.internal" {
		t.Fatalf("OOB host = %q, want host.docker.internal (127.0.0.1 is unreachable from the target container)", val)
	}
}

// TestInvestigateEnv_OperatorOverrideWins: a real operator value (e.g. a Linux host-gateway IP or a
// remote collector) must NOT be clobbered — the injected default is only a fallback.
func TestInvestigateEnv_OperatorOverrideWins(t *testing.T) {
	env := investigateEnv([]string{"PATH=/usr/bin", "TSENGINE_OOB_HOST=172.17.0.1"})
	n, val := countKey(env, "TSENGINE_OOB_HOST")
	if n != 1 || val != "172.17.0.1" {
		t.Fatalf("operator override lost: got %d entries, val=%q, want 1 entry = 172.17.0.1", n, val)
	}
}

// TestInvestigateEnv_EmptyOverrideReplaced: an EMPTY TSENGINE_OOB_HOST= (which oobHost() treats as unset)
// must be replaced by the default, with no duplicate key left behind (exec dedup is platform-dependent).
func TestInvestigateEnv_EmptyOverrideReplaced(t *testing.T) {
	env := investigateEnv([]string{"TSENGINE_OOB_HOST=", "PATH=/usr/bin"})
	n, val := countKey(env, "TSENGINE_OOB_HOST")
	if n != 1 {
		t.Fatalf("want exactly one TSENGINE_OOB_HOST entry (empty one replaced, not duplicated), got %d in %v", n, env)
	}
	if val != "host.docker.internal" {
		t.Fatalf("empty override not replaced: OOB host = %q, want host.docker.internal", val)
	}
}
