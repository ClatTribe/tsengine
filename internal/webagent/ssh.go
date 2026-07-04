package webagent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ssh.go adds credential-based SSH lateral movement — the EXPLOIT step for a leaked-credential
// finding. The agent routinely DISCOVERS creds over HTTP (an info-disclosure / source leak / config
// dump reveals a username+password or a private key), but had no way to USE them: the flag / the next
// hop lives behind SSH, not HTTP, so the chain dead-ended at "I found SSH creds pedro:… but can't
// read /home/pedro/FLAG.txt". ssh_exec connects with the discovered creds and runs ONE command,
// returning its output — turning a discovered credential into a proven lateral-movement finding.
//
// Host-side (§12.6): the offensive agent owns its own network I/O, like browser_render / oob_url — no
// sandbox, no image rebuild. Scope-guarded like send_request (the SSH host must be in the authorized
// surface — checked at HOST granularity because SSH:22 is a different port from the web app but the
// same authorized box) and bounded (dial + handshake timeout, capped output) so it can't hang or dump
// unbounded data. Grounded (§10): it returns exactly what the server sent; the agent still records the
// finding from real output. §13-clean: it wraps the standard SSH protocol (golang.org/x/crypto/ssh),
// not an in-house detector.

const sshMaxOutput = 12 << 10 // 12KB cap on returned command output (evidence, not a file dump)

// tSSHExec runs one command over SSH with agent-supplied credentials.
//
//	host        optional — the SSH host (defaults to the target's host; must be IN SCOPE)
//	port        optional — default 22
//	user        required — the SSH username (e.g. leaked from a source disclosure)
//	password    optional — password auth
//	private_key optional — PEM private-key auth (alternative to password)
//	command     required — the shell command to run (e.g. "cat /home/pedro/FLAG.txt")
func tSSHExec(cc *Context, args map[string]any) string {
	host := strings.TrimSpace(argStr(args, "host"))
	if host == "" {
		host = hostname(cc.Target) // common case: SSH on the same box as the web app
	}
	if host == "" {
		return "ERROR: no host — pass host=<ssh-host>"
	}
	if cc.req == nil || !cc.req.HostInScope(host) {
		return fmt.Sprintf("ERROR: host %q is out of scope — ssh_exec only reaches the authorized target surface", host)
	}
	user := strings.TrimSpace(argStr(args, "user"))
	if user == "" {
		return "ERROR: no user — pass user=<ssh-username> (e.g. one leaked from a source disclosure)"
	}
	command := strings.TrimSpace(argStr(args, "command"))
	if command == "" {
		return "ERROR: no command — pass command=<shell command>, e.g. command=\"cat /home/<user>/FLAG.txt\""
	}
	port := 22
	if p := strings.TrimSpace(argStr(args, "port")); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	var auth []ssh.AuthMethod
	if pw := argStr(args, "password"); pw != "" {
		auth = append(auth, ssh.Password(pw))
	}
	if key := strings.TrimSpace(argStr(args, "private_key")); key != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(key)); err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		} else {
			return "ERROR: private_key did not parse as a PEM private key: " + err.Error()
		}
	}
	if len(auth) == 0 {
		return "ERROR: no credentials — pass password=<pw> or private_key=<pem>"
	}

	out, err := sshExec(cc.ctx, net.JoinHostPort(host, strconv.Itoa(port)), user, auth, command)
	if err != nil {
		return fmt.Sprintf("SSH FAILED (%s@%s:%d): %s", user, host, port, err.Error())
	}
	if len(out) > sshMaxOutput {
		out = out[:sshMaxOutput] + "\n…(truncated)"
	}
	note := ""
	if strings.Contains(out, "flag{") {
		note = " — output contains a flag{…}; record the lateral-movement finding citing this turn"
	}
	return fmt.Sprintf("SSH %s@%s:%d ran %q%s\n%s", user, host, port, command, note, out)
}

// sshExec is the pure connect→run→return core (unit-tested against an in-process SSH server). A
// non-zero remote exit is NOT an error — the command's output (which may hold the flag / an error the
// agent must read) is returned regardless, mirroring how sqlmap's wrapper parses stdout on exit≠0.
//
// Output is captured by draining the stdout+stderr PIPES to EOF (the channel close) BEFORE Wait,
// each in its own goroutine into its own buffer. Setting sess.Stdout=&buf + sess.Run() is subtly
// racy: Run's Wait can return on the exit-status message before the internal stdout copier goroutine
// has flushed, so under load the buffer reads back EMPTY even though the command produced output
// (observed live — a flag-bearing `cat` came back blank ~1 in 3). Draining the pipes ourselves and
// only then calling Wait removes the race: io.Copy blocks until the channel EOFs, so every byte is in
// hand before we return.
func sshExec(ctx context.Context, addr, user string, auth []ssh.AuthMethod, command string) (string, error) {
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: auth,
		// A pentest tool doesn't pre-know the target's host key (the whole point is reaching an
		// unmanaged box with leaked creds), so we don't pin it — same posture as the app under test
		// (paramiko AutoAddPolicy). We never persist a known_hosts, so there's nothing to poison.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("ssh handshake/auth: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("ssh stdout pipe: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("ssh stderr pipe: %w", err)
	}
	if err := sess.Start(command); err != nil {
		return "", fmt.Errorf("ssh start: %w", err)
	}
	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&outBuf, stdout) }() //nolint:errcheck // EOF-drain; content is the evidence
	go func() { defer wg.Done(); io.Copy(&errBuf, stderr) }() //nolint:errcheck
	wg.Wait()          // both pipes drained to channel-close — all output captured
	waitErr := sess.Wait() // reap exit status; a non-zero exit is fine (output already in hand)

	out := outBuf.String()
	if errBuf.Len() > 0 {
		out += errBuf.String() // stderr often carries the useful message (Permission denied, No such file)
	}
	// Only a transport failure with NO output at all is fatal; a remote non-zero exit that produced
	// output (or none) is reported through the output, not as a tool error.
	if waitErr != nil {
		if _, ok := waitErr.(*ssh.ExitError); !ok && out == "" {
			return "", fmt.Errorf("ssh run: %w", waitErr)
		}
	}
	return out, nil
}

// hostname returns the bare host (no port) of a raw URL, or "" if it doesn't parse.
func hostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
