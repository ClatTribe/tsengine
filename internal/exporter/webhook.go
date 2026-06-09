package exporter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/report"
)

// Event is the normalized finding/case payload tsengine POSTs to a downstream
// system (SIEM / SOC / AI-SOC / ticketing). It is intentionally small and stable:
// both sides speak the same severity ladder + MITRE-friendly fields, so a consumer
// can open a case directly.
type Event struct {
	Source      string         `json:"source"` // always "tsengine"
	Kind        string         `json:"kind"`   // assessment kind
	Target      string         `json:"target"`
	GeneratedAt time.Time      `json:"generated_at"`
	RiskRating  string         `json:"risk_rating"`
	Signed      bool           `json:"signed,omitempty"`
	Signer      string         `json:"signer,omitempty"`
	Counts      map[string]int `json:"severity_counts"`
	Findings    []EventFinding `json:"findings"`
}

// EventFinding is one finding in the outbound payload.
type EventFinding struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Severity    string              `json:"severity"`
	Status      string              `json:"status,omitempty"` // verified | corroborated | pattern_match
	Endpoint    string              `json:"endpoint,omitempty"`
	Tool        string              `json:"tool,omitempty"`
	CWE         []string            `json:"cwe,omitempty"`
	ThreatIntel string              `json:"threat_intel,omitempty"`
	Compliance  map[string][]string `json:"compliance,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	Evidence    []string            `json:"evidence,omitempty"`
}

// EventFromReport builds the outbound event from a normalized report.
func EventFromReport(r *report.Report, now time.Time) Event {
	ev := Event{
		Source: "tsengine", Kind: r.Kind, Target: r.Target, GeneratedAt: now.UTC(),
		RiskRating: r.RiskRating(), Signed: r.Signed, Signer: r.Signer,
		Counts: r.Counts(),
	}
	for _, f := range r.Findings {
		ev.Findings = append(ev.Findings, EventFinding{
			ID: f.ID, Title: f.Title, Severity: f.Severity, Status: f.Status,
			Endpoint: f.Endpoint, Tool: f.Tool, CWE: f.CWE, ThreatIntel: f.ThreatIntel,
			Compliance: f.Compliance, Remediation: f.Remediation, Evidence: f.Evidence,
		})
	}
	return ev
}

// EmitOptions configures the POST.
type EmitOptions struct {
	URL        string
	Token      string // optional bearer token
	HMACSecret string // optional: HMAC-SHA256 of the body → X-TSEngine-Signature
	Client     *http.Client
}

// Emit POSTs the event as JSON. It signs the body (HMAC-SHA256, sha256=<hex>) when a
// secret is set so the receiver can verify integrity + origin. Returns the response
// status; a non-2xx status is an error.
func Emit(ctx context.Context, ev Event, opts EmitOptions) (int, error) {
	if opts.URL == "" {
		return 0, fmt.Errorf("emit: no webhook URL")
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 15 * time.Second}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tsengine-exporter")
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}
	if opts.HMACSecret != "" {
		req.Header.Set("X-TSEngine-Signature", "sha256="+Sign(body, opts.HMACSecret))
	}
	resp, err := opts.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("emit: webhook returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// Sign returns the hex HMAC-SHA256 of body under secret (the value used in the
// X-TSEngine-Signature header, minus the "sha256=" prefix). Exposed so receivers
// (and tests) can verify.
func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
