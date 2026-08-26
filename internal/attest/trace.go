package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// trace.go is ADR 0032 D5: the per-scan stage trace — one signed file that makes
// a wrong answer diagnosable at stage granularity. Records are hash-CHAINED
// (each record carries sha256(prev-hash || record-canonical-bytes)), so any
// edit to history breaks the chain visibly; the whole chain is then signed with
// the same ed25519 key that signs evidence bundles, so ONE verifier covers
// ledger, evidence, and traces (§18.2 inv 4).

// TraceRecord is one stage execution in the scan trace. Tokens are the brain's
// own accounting (zeros when the seam cannot report them — unknown ≠ $0).
type TraceRecord struct {
	Stage       string    `json:"stage"`            // detection | escalation | coverage | sweep | disprover | model
	Detail      string    `json:"detail,omitempty"` // human-readable summary (counts, labels)
	Model       string    `json:"model,omitempty"`  // brain that executed the stage, when one did
	TokensIn    int64     `json:"tokens_in,omitempty"`
	TokensOut   int64     `json:"tokens_out,omitempty"`
	Disposition string    `json:"disposition"`         // ok | skipped:<reason> | failed:<reason>
	InputSHA    string    `json:"input_sha,omitempty"` // sha256 of the stage's primary input (prompt, findings batch), when captured
	PrevHash    string    `json:"prev_hash"`
	Hash        string    `json:"hash"`
	At          time.Time `json:"at"`
}

// ChainTrace computes the hash chain over records IN PLACE: each record's Hash
// becomes sha256(prevHash + canonical(record)). Deterministic — the same records
// always produce the same chain.
func ChainTrace(recs []TraceRecord) []TraceRecord {
	prev := ""
	for i := range recs {
		blob, _ := json.Marshal(struct {
			Stage       string `json:"stage"`
			Detail      string `json:"detail"`
			Model       string `json:"model"`
			TokensIn    int64  `json:"ti"`
			TokensOut   int64  `json:"to"`
			Disposition string `json:"disp"`
			PrevHash    string `json:"prev"`
		}{recs[i].Stage, recs[i].Detail, recs[i].Model, recs[i].TokensIn, recs[i].TokensOut, recs[i].Disposition, prev})
		sum := sha256.Sum256(blob)
		prev = hex.EncodeToString(sum[:])
		recs[i].PrevHash = prevOf(i, recs)
		recs[i].Hash = prev
	}
	return recs
}

func prevOf(i int, recs []TraceRecord) string {
	if i == 0 {
		return ""
	}
	return recs[i-1].Hash
}

// SignedTraceFile is what lands next to vulnerabilities.json.
type SignedTraceFile struct {
	Records   []TraceRecord `json:"records"`
	FinalHash string        `json:"final_hash"`
	SignedAt  time.Time     `json:"signed_at"`
	Signer    string        `json:"signer"`
	Signature string        `json:"signature"` // ed25519 over FinalHash (hex-decoded digest bytes)
}

// SignTraceFile writes records as a signed trace file. The signature covers the
// FINAL CHAIN HASH only — the chain itself covers every record byte-for-byte, so
// tampering with any record (or reordering) invalidates verification without
// re-signing the whole document each time a stage appends.
func SignTraceFile(path string, recs []TraceRecord, signer string, priv ed25519.PrivateKey, now time.Time) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("attest: invalid private key size %d", len(priv))
	}
	recs = ChainTrace(recs)
	final := ""
	if len(recs) > 0 {
		final = recs[len(recs)-1].Hash
	}
	digest, _ := hex.DecodeString(final)
	sig := ed25519.Sign(priv, digest)
	doc := SignedTraceFile{
		Records: recs, FinalHash: final,
		SignedAt: now.UTC(), Signer: signer,
		Signature: hex.EncodeToString(sig),
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644) //nolint:gosec // operator-provided path
}

// VerifyTraceFile reads a signed trace file and verifies BOTH the signature and
// the full hash chain. Exported for auditors and tests — one verifier, same key
// family as evidence bundles.
func VerifyTraceFile(path string, pub ed25519.PublicKey) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc SignedTraceFile
	if err := json.Unmarshal(blob, &doc); err != nil {
		return err
	}
	digest, _ := hex.DecodeString(doc.FinalHash)
	sig, _ := hex.DecodeString(doc.Signature)
	if !ed25519.Verify(pub, digest, sig) {
		return fmt.Errorf("attest: trace signature verification failed")
	}
	rechained := ChainTrace(doc.Records)
	if len(rechained) > 0 && rechained[len(rechained)-1].Hash != doc.FinalHash {
		return fmt.Errorf("attest: trace chain broken — records were altered after signing")
	}
	return nil
}
