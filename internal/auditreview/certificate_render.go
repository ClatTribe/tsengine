package auditreview

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
)

// certificate_render.go is the DOCUMENT half of the certificate: the attestation a reader can
// verify, and the printable forms a customer attaches to a hosting request.
//
// Certify (certificate.go) decides WHETHER a certificate may exist and generates the sentence the
// auditor signs. This file never revisits that decision — it renders what Certify produced, and it
// refuses to sign anything Certify did not issue. Two renderers rather than one template: Markdown
// is what travels in a ticket or an email, and the HTML is the one-page print form a data centre
// files. Both carry the same facts in the same order, and neither adds a claim the JSON does not
// hold, so the three forms of one certificate cannot disagree.

// Attestation is the platform key's signature over the certificate body — the SAME ed25519-over-
// canonical-JSON scheme as the compliance evidence pack, so one verifier covers both artifacts.
// An alias, not a copy: two attestation structs would be two formats free to drift apart.
type Attestation = grc.Attestation

// certificateValidity is the ceiling on a certificate's life. Twelve months is the re-audit cadence
// the tenders these certificates serve, and CERT-In's audit guidance, both assume. It is a CEILING:
// the certificate describes the application on the date of issue, and a change to it voids the
// statement earlier.
const certificateValidity = 365 * 24 * time.Hour

// issueID derives the certificate number from the target, the auditor and the DAY of issue.
// Deterministic so the same audit downloaded twice on the same day is one document, not two
// numbers for one certificate; day-granular so a re-issue after a change is a new certificate.
func issueID(target, auditor string, issued time.Time) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(target)) + "|" + strings.ToLower(strings.TrimSpace(auditor)) + "|" + issued.UTC().Format("2006-01-02")))
	return "STH-" + strings.ToUpper(hex.EncodeToString(sum[:6]))
}

// Sign attests the certificate. It refuses a certificate with no statement — the only way to hold
// one is to have bypassed Certify, and a signature on that would lend authority to a document the
// package declined to issue.
func Sign(c *Certificate, signer string, priv ed25519.PrivateKey, now time.Time) error {
	if c == nil || strings.TrimSpace(c.Statement) == "" || strings.TrimSpace(c.Auditor) == "" {
		return errors.New("auditreview: certificate was not issued — nothing to sign")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("auditreview: invalid private key length %d", len(priv))
	}
	if strings.TrimSpace(signer) == "" {
		return errors.New("auditreview: empty signer")
	}
	body, err := canon(c)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(priv, sum[:])
	c.Attestation = &Attestation{
		SHA256: hex.EncodeToString(sum[:]), SignedAt: now.UTC(), Signer: signer, Signature: hex.EncodeToString(sig),
	}
	return nil
}

// Verify checks the attestation against the certificate body, so a reader holding the JSON can
// prove it was not altered after the platform signed it.
func Verify(c *Certificate, pub ed25519.PublicKey) error {
	if c == nil || c.Attestation == nil {
		return errors.New("auditreview: missing attestation")
	}
	body, err := canon(c)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != c.Attestation.SHA256 {
		return errors.New("auditreview: hash mismatch — certificate altered after signing")
	}
	sig, err := hex.DecodeString(c.Attestation.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, sum[:], sig) {
		return errors.New("auditreview: signature does not verify")
	}
	return nil
}

func canon(c *Certificate) ([]byte, error) {
	clone := *c
	clone.Attestation = nil
	return json.Marshal(clone)
}

// RenderMarkdown is the certificate as a document. The signed statement is quoted VERBATIM — it is
// the sentence the auditor put their name to, and a renderer that paraphrased it would be a second
// author of a signed document.
func RenderMarkdown(c *Certificate) string {
	var b strings.Builder
	b.WriteString("# Safe-to-Host Certificate\n\n")
	if c.ID != "" {
		fmt.Fprintf(&b, "**Certificate no.:** `%s`  \n", c.ID)
	}
	fmt.Fprintf(&b, "**Application:** `%s`  \n", c.Target)
	if c.Standard != "" {
		fmt.Fprintf(&b, "**Assessed against:** %s  \n", c.Standard)
	}
	fmt.Fprintf(&b, "**Issued:** %s  \n", c.IssuedAt.UTC().Format("2 January 2006"))
	if !c.ValidUntil.IsZero() {
		fmt.Fprintf(&b, "**Valid until:** %s, or until the application is changed, whichever is earlier\n", c.ValidUntil.UTC().Format("2 January 2006"))
	}
	b.WriteString("\n## Statement\n\n")
	b.WriteString(c.Statement)
	b.WriteString("\n\n## What was reviewed\n\n")
	fmt.Fprintf(&b, "- Findings reviewed: %d (included %d, excluded with reasons recorded %d)\n", c.FindingsReviewed, c.Included, c.Excluded)
	if line := openLine(c.OpenBySeverity); line != "" {
		fmt.Fprintf(&b, "- Open at issue: %s\n", line)
	} else {
		b.WriteString("- Open at issue: none\n")
	}
	if len(c.NotTested) > 0 {
		b.WriteString("- Not covered by this assessment:\n")
		for _, n := range c.NotTested {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	b.WriteString("\n## Auditor\n\n")
	fmt.Fprintf(&b, "**Signed by:** %s  \n", c.Auditor)
	switch c.Capacity {
	case "internal", "":
		b.WriteString("**Capacity:** the organisation's own staff (self-assessment)  \n")
	default:
		fmt.Fprintf(&b, "**Firm:** %s  \n", orNotRecorded(c.Firm))
	}
	fmt.Fprintf(&b, "\n**Assessment engine:** %s", orNotRecorded(c.Engine))
	if c.Brand != "" {
		fmt.Fprintf(&b, " · **Issued by:** %s", c.Brand)
	}
	b.WriteString("\n")
	if at := c.Attestation; at != nil {
		fmt.Fprintf(&b, "\n---\n**Attestation:** SHA-256 `%s` · signed %s by `%s` (ed25519)\n", at.SHA256, at.SignedAt.UTC().Format(time.RFC3339), at.Signer)
	}
	b.WriteString("\n_The audit report, with every finding, its evidence, the reviewer's decisions and their reasons, accompanies this certificate and is the document of record._\n")
	return b.String()
}

// RenderHTML is the print-ready form — what a customer saves as PDF and attaches to a hosting
// request. Deliberately plain: one page, no chrome, nothing that depends on a stylesheet being
// fetched, and every value HTML-escaped because the target and the auditor's name are user data.
func RenderHTML(c *Certificate) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Safe-to-Host Certificate</title><style>
body{font-family:Georgia,serif;max-width:760px;margin:40px auto;padding:0 24px;color:#111;line-height:1.5}
h1{font-size:26px;letter-spacing:.02em;border-bottom:2px solid #111;padding-bottom:8px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;margin-top:28px}
table{border-collapse:collapse}td{padding:3px 12px 3px 0;vertical-align:top}td:first-child{font-weight:bold;white-space:nowrap}
code{font-family:Menlo,monospace;font-size:12px}.fine{font-size:12px;color:#555}ul{margin:4px 0}
@media print{body{margin:0}}
</style></head><body><h1>Safe-to-Host Certificate</h1><table>`)
	row := func(k, v string) { fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>", e(k), v) }
	if c.ID != "" {
		row("Certificate no.", "<code>"+e(c.ID)+"</code>")
	}
	row("Application", "<code>"+e(c.Target)+"</code>")
	if c.Standard != "" {
		row("Assessed against", e(c.Standard))
	}
	row("Issued", e(c.IssuedAt.UTC().Format("2 January 2006")))
	if !c.ValidUntil.IsZero() {
		row("Valid until", e(c.ValidUntil.UTC().Format("2 January 2006"))+", or until the application is changed, whichever is earlier")
	}
	b.WriteString("</table><h2>Statement</h2><p>")
	b.WriteString(e(c.Statement))
	b.WriteString("</p><h2>What was reviewed</h2><ul>")
	fmt.Fprintf(&b, "<li>Findings reviewed: %d (included %d, excluded with reasons recorded %d)</li>", c.FindingsReviewed, c.Included, c.Excluded)
	if line := openLine(c.OpenBySeverity); line != "" {
		fmt.Fprintf(&b, "<li>Open at issue: %s</li>", e(line))
	} else {
		b.WriteString("<li>Open at issue: none</li>")
	}
	if len(c.NotTested) > 0 {
		b.WriteString("<li>Not covered by this assessment:<ul>")
		for _, n := range c.NotTested {
			fmt.Fprintf(&b, "<li>%s</li>", e(n))
		}
		b.WriteString("</ul></li>")
	}
	b.WriteString("</ul><h2>Auditor</h2><table>")
	row("Signed by", e(c.Auditor))
	switch c.Capacity {
	case "internal", "":
		row("Capacity", "the organisation's own staff (self-assessment)")
	default:
		row("Firm", e(orNotRecorded(c.Firm)))
	}
	b.WriteString("</table>")
	fmt.Fprintf(&b, `<p class="fine">Assessment engine: %s`, e(orNotRecorded(c.Engine)))
	if c.Brand != "" {
		fmt.Fprintf(&b, ` · Issued by: %s`, e(c.Brand))
	}
	b.WriteString("</p>")
	if at := c.Attestation; at != nil {
		fmt.Fprintf(&b, `<p class="fine">Attestation: SHA-256 <code>%s</code> · signed %s by <code>%s</code> (ed25519)</p>`, e(at.SHA256), e(at.SignedAt.UTC().Format(time.RFC3339)), e(at.Signer))
	}
	b.WriteString(`<p class="fine">The audit report, with every finding, its evidence, the reviewer's decisions and their reasons, accompanies this certificate and is the document of record.</p></body></html>`)
	return b.String()
}

// openLine renders the open counts worst-first; empty when nothing is open.
func openLine(open map[string]int) string {
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if open[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, open[s]))
		}
	}
	return strings.Join(parts, ", ")
}

func orNotRecorded(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}
