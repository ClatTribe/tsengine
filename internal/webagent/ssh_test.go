package webagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer spins an in-process SSH server that accepts password auth for (user,pass) and,
// on any exec request, writes wantOut then exit-status 0. Returns "host", port. It proves ssh_exec
// really speaks SSH (handshake + password auth + exec), not a stub.
func startTestSSHServer(t *testing.T, user, pass, wantOut string) (string, int) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, errBadAuth
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOneSSH(nConn, cfg, wantOut)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return "127.0.0.1", port
}

var errBadAuth = &sshAuthErr{}

type sshAuthErr struct{}

func (*sshAuthErr) Error() string { return "auth failed" }

// serveOneSSH handles a single connection: handshake, accept the session channel, answer any exec
// request with wantOut + exit-status 0.
func serveOneSSH(nConn net.Conn, cfg *ssh.ServerConfig, wantOut string) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		nConn.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range chReqs {
				if req.Type == "exec" {
					req.Reply(true, nil)
					ch.Write([]byte(wantOut))
					// exit-status payload: 4-byte big-endian status 0
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					ch.Close()
					return
				}
				req.Reply(false, nil)
			}
		}()
	}
}

func testCtx(t *testing.T, allowHosts []string) *Context {
	t.Helper()
	return &Context{
		Target: "http://" + allowHosts[0],
		ctx:    context.Background(),
		req:    NewRequester(allowHosts, 50, 0),
	}
}

// TestSSHExec_ReadsFlag: the whole lateral-movement chain — leaked creds → ssh_exec → command output
// carrying the flag surfaced to the agent. This is the XBEN-042 shape (source disclosure leaks
// pedro's SSH creds; the flag is at /home/pedro/FLAG.txt, reachable only over SSH).
func TestSSHExec_ReadsFlag(t *testing.T) {
	host, port := startTestSSHServer(t, "pedro", "AHeavySandbag!", "flag{ssh-lateral-movement}\n")
	cc := testCtx(t, []string{host + ":" + strconv.Itoa(port)})

	out := tSSHExec(cc, map[string]any{
		"host": host, "port": strconv.Itoa(port),
		"user": "pedro", "password": "AHeavySandbag!",
		"command": "cat /home/pedro/FLAG.txt",
	})
	if !strings.Contains(out, "flag{ssh-lateral-movement}") {
		t.Fatalf("ssh_exec did not return the flag: %s", out)
	}
	if !strings.Contains(out, "contains a flag") {
		t.Errorf("ssh_exec did not flag the flag-bearing output to the agent: %s", out)
	}
	// The output must be RECORDED as a citable evidence turn — else the flag never reaches the
	// transcript / signed evidence bundle the grader (and a real customer) reads, so the lateral-movement
	// capture is invisible. Observed live on XBEN-042: ssh_exec read the flag but the run graded unsolved
	// because the SSH output was not in the evidence.
	if len(cc.History) == 0 {
		t.Fatal("ssh_exec recorded NO evidence turn — the SSH output (with the flag) is invisible to the transcript/evidence")
	}
	last := cc.History[len(cc.History)-1]
	if last.Method != "ssh_exec" || !strings.Contains(last.RespSnippet, "flag{ssh-lateral-movement}") {
		t.Errorf("ssh_exec evidence turn missing the flag output: %+v", last)
	}
}

// TestSSHExec_NumericPort: an LLM naturally passes port as a NUMBER (JSON float64), not a string. The
// arg parser must accept it — else the numeric port is dropped, ssh_exec defaults to 22, and it can't
// reach a non-standard published SSH port. Observed live on XBEN-042: the container's SSH is published
// on a high host port; a numeric port silently fell back to 22 → "connection refused".
func TestSSHExec_NumericPort(t *testing.T) {
	host, port := startTestSSHServer(t, "pedro", "pw", "flag{numeric-port}\n")
	cc := testCtx(t, []string{host + ":" + strconv.Itoa(port)})
	out := tSSHExec(cc, map[string]any{
		"host": host, "port": float64(port), // JSON numbers decode as float64 — as an LLM sends them
		"user": "pedro", "password": "pw", "command": "cat /flag",
	})
	if !strings.Contains(out, "flag{numeric-port}") {
		t.Fatalf("ssh_exec with a NUMERIC port did not connect/return the flag (port likely dropped to 22): %s", out)
	}
}

// TestSSHExec_OutOfScopeRefused: a host outside the authorized surface is refused before any dial —
// ssh_exec can never reach a host the LLM invents.
func TestSSHExec_OutOfScopeRefused(t *testing.T) {
	cc := testCtx(t, []string{"localhost:8080"})
	out := tSSHExec(cc, map[string]any{
		"host": "evil.example.com", "user": "root", "password": "x", "command": "id",
	})
	if !strings.Contains(out, "out of scope") {
		t.Fatalf("expected out-of-scope refusal, got: %s", out)
	}
}

// TestSSHExec_ScopeIsHostGranular: SSH on port 22 is in scope when the same HOST is authorized on a
// different (web) port — the box is authorized, not one port.
func TestSSHExec_ScopeIsHostGranular(t *testing.T) {
	r := NewRequester([]string{"target.local:49770"}, 10, 0)
	if !r.HostInScope("target.local") {
		t.Error("same host on a different service port should be in scope")
	}
	if r.HostInScope("other.local") {
		t.Error("a different host must be out of scope")
	}
}

// TestSSHExec_MissingArgs: guard-rail errors are explicit (no silent dial with half the inputs).
func TestSSHExec_MissingArgs(t *testing.T) {
	cc := testCtx(t, []string{"localhost:80"})
	if out := tSSHExec(cc, map[string]any{"host": "localhost", "command": "id"}); !strings.Contains(out, "no user") {
		t.Errorf("missing user not reported: %s", out)
	}
	if out := tSSHExec(cc, map[string]any{"host": "localhost", "user": "root", "password": "x"}); !strings.Contains(out, "no command") {
		t.Errorf("missing command not reported: %s", out)
	}
	if out := tSSHExec(cc, map[string]any{"host": "localhost", "user": "root", "command": "id"}); !strings.Contains(out, "no credentials") {
		t.Errorf("missing credentials not reported: %s", out)
	}
}

// TestSSHExec_BadAuthFails: wrong password fails cleanly (no false success).
func TestSSHExec_BadAuthFails(t *testing.T) {
	host, port := startTestSSHServer(t, "pedro", "right", "flag{nope}\n")
	cc := testCtx(t, []string{host + ":" + strconv.Itoa(port)})
	out := tSSHExec(cc, map[string]any{
		"host": host, "port": strconv.Itoa(port), "user": "pedro", "password": "wrong", "command": "id",
	})
	if !strings.Contains(out, "SSH FAILED") {
		t.Fatalf("bad auth should fail, got: %s", out)
	}
	if strings.Contains(out, "flag{") {
		t.Fatalf("bad auth must not leak output: %s", out)
	}
}

// startTestSSHServerPubkey spins an in-process SSH server that accepts ONE authorized public key
// (any user), and answers exec with wantOut. Proves ssh_exec's private-key auth path end to end.
func startTestSSHServerPubkey(t *testing.T, authorized ssh.PublicKey, wantOut string) (string, int) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errBadAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOneSSH(nConn, cfg, wantOut)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return "127.0.0.1", port
}

// TestSSHExec_EncryptedPrivateKeyWithPassphrase: a leaked id_rsa is often passphrase-protected;
// ssh_exec must decrypt it with a supplied passphrase and authenticate. Regression for the gap where
// only unencrypted keys and passwords worked.
func TestSSHExec_EncryptedPrivateKeyWithPassphrase(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "leaked", []byte("s3cr3t-pass"))
	if err != nil {
		t.Fatalf("marshal encrypted key: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(block))

	host, port := startTestSSHServerPubkey(t, sshPub, "flag{ssh-encrypted-key}\n")
	cc := testCtx(t, []string{host + ":" + strconv.Itoa(port)})

	// correct passphrase → authenticates → reads the flag
	out := tSSHExec(cc, map[string]any{
		"host": host, "port": strconv.Itoa(port), "user": "pedro",
		"private_key": pemKey, "passphrase": "s3cr3t-pass", "command": "cat /flag",
	})
	if !strings.Contains(out, "flag{ssh-encrypted-key}") {
		t.Fatalf("encrypted-key auth failed: %s", out)
	}

	// encrypted key WITHOUT a passphrase → actionable hint, no silent failure
	out = tSSHExec(cc, map[string]any{
		"host": host, "port": strconv.Itoa(port), "user": "pedro",
		"private_key": pemKey, "command": "cat /flag",
	})
	if !strings.Contains(out, "passphrase-protected") {
		t.Fatalf("expected a passphrase-protected hint, got: %s", out)
	}
}
