// Package padbuster wraps the padbuster padding-oracle attack tool as a tsengine Tool. It is the
// CRYPTO specialist reached via dispatch_oss / tool-replay: given an AES-CBC (or any block-cipher)
// PKCS7 padding oracle, padbuster DECRYPTS a ciphertext byte-by-byte OR ENCRYPTS arbitrary plaintext
// (forge mode, -plaintext) — the char-by-char work that's infeasible in the agent's request budget,
// exactly the §13 sqlmap-shaped case. Registers via init().
package padbuster

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// Padbuster is the tool.Tool implementation.
type Padbuster struct{}

// New constructs a Padbuster wrapper.
func New() *Padbuster { return &Padbuster{} }

func (*Padbuster) Name() string           { return "padbuster" }
func (*Padbuster) SandboxExecution() bool { return true }

// T1600 = Weaken Encryption (padding-oracle recovery of plaintext / forging of ciphertext).
func (*Padbuster) MITRETechniques() []string { return []string{"T1600"} }

// Run drives a padding-oracle attack against one endpoint.
//
// Recognized args (padbuster's own CLI is `padbuster URL EncryptedSample BlockSize [options]`):
//
//	"target"     string — required, the oracle URL.
//	"sample"     string — required, the encrypted sample (cookie/param ciphertext) to attack.
//	"block_size" string — cipher block size (default "16" for AES); "8" for DES/3DES.
//	"cookies"    string — cookie(s) carrying the sample, e.g. "auth=<sample>".
//	"error"      string — the padding-error signature string (the oracle); omit to auto-detect.
//	"encoding"   string — sample encoding: 0=Base64 1=LowerHex 2=UpperHex 3=.NET-UrlToken 4=WebSafeB64.
//	"plaintext"  string — FORGE mode: encrypt this plaintext into a valid ciphertext.
//	"post"       string — POST body (switches the oracle request to POST).
//	"headers"    string — extra request headers.
//	"no_iv"      bool   — the sample has no prepended IV (-noiv).
func (*Padbuster) Run(ctx context.Context, args tool.Args) (tool.Result, error) {
	cli, err := buildCLI(args)
	if err != nil {
		return tool.Result{}, err
	}
	cmd := exec.CommandContext(ctx, "padbuster", cli...)
	// padbuster prompts "Do you want to use this value (Yes/No/All)?" per recovered byte; the sandbox
	// tool-server has no TTY. Feed "A" (All) — padbuster then auto-accepts every value without asking,
	// so the whole decrypt runs unattended. Bounded stream (EOFs, never hangs).
	cmd.Stdin = strings.NewReader(strings.Repeat("a\n", 64))
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return tool.Result{}, fmt.Errorf("padbuster: exec: %w", err)
		}
		// padbuster exits non-zero on a failed/partial run; return stdout anyway for the caller.
	}
	return tool.Result{Output: string(stdout)}, nil
}

// buildCLI assembles the padbuster argv (pure — no exec, so it's unit-tested). padbuster takes three
// POSITIONAL args (URL, sample, blocksize) then dash-options.
func buildCLI(args tool.Args) ([]string, error) {
	target := strings.TrimSpace(str(args, "target"))
	sample := strings.TrimSpace(str(args, "sample"))
	if target == "" || sample == "" {
		return nil, errors.New("padbuster: 'target' and 'sample' are required")
	}
	block := strings.TrimSpace(str(args, "block_size"))
	if block == "" {
		block = "16" // AES default
	}
	cli := []string{target, sample, block}
	for _, m := range []struct{ key, flag string }{
		{"error", "-error"},
		{"encoding", "-encoding"},
		{"cookies", "-cookies"},
		{"plaintext", "-plaintext"},
		{"post", "-post"},
		{"headers", "-headers"},
	} {
		if v := strings.TrimSpace(str(args, m.key)); v != "" {
			cli = append(cli, m.flag, v)
		}
	}
	if b, ok := args["no_iv"].(bool); ok && b {
		cli = append(cli, "-noiv")
	}
	// -noencode: do NOT URL-encode the manipulated ciphertext. REQUIRED for a base64-cookie oracle —
	// without it padbuster percent-encodes the base64 (=,/,+) so the server's b64decode always fails
	// and EVERY response looks like invalid padding ("No matching response on Byte N"). Proven live on
	// XBEN-101: the decrypt only progresses with -noencode.
	if b, ok := args["no_encode"].(bool); ok && b {
		cli = append(cli, "-noencode")
	}
	// NOTE: padbuster has no -noninteractive flag; it runs unattended when "-error <sig>" pins the
	// oracle (else it prompts to identify the padding-error response — pass `error` for a clean run).
	// Run() also feeds an auto-answer stdin so any residual prompt can't hang the tool-server (no TTY).
	return cli, nil
}

func str(args tool.Args, k string) string {
	s, _ := args[k].(string)
	return s
}

// KnownArgs declares the recognized arg keys (tool.ArgSpec).
func (*Padbuster) KnownArgs() []string {
	return []string{"target", "sample", "block_size", "error", "encoding", "cookies", "plaintext", "post", "headers", "no_iv", "no_encode"}
}

func init() { tool.Register(New()) }
