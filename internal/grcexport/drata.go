// Package grcexport pushes the engine's control posture INTO the compliance platforms a customer
// already runs — Drata first — as evidence records those platforms' own tests evaluate.
//
// The shape of the integration is dictated by theirs, and it is worth being precise about it,
// because it is the honest one. Drata's Custom Connections accept RECORDS (structured JSON rows)
// and the pass/fail TESTS over those records are authored in Drata's dashboard by the customer and
// mapped to controls there. So we never tell Drata a control is met: we push, per framework control,
// the facts we hold — met or gap, how many findings cite it, where the evidence is — and their test
// decides. Nothing here asserts anything the engine did not assess (§10); a control the engine has
// not assessed is simply not a record, never a "met" row.
//
// A push is the FULL STATE, via Drata's session upload: every record in one session, then
// "complete", which atomically replaces the previous batch. A control that stopped being a gap
// disappears from the set rather than lingering as a stale row, and a partial push that fails
// midway replaces nothing.
package grcexport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Record is one control's posture as a Drata custom-connection row. The `id` is stable per
// framework+control so a re-push updates rather than duplicates.
type Record struct {
	ID            string `json:"id"`
	Framework     string `json:"framework"`
	ControlID     string `json:"control_id"`
	Control       string `json:"control"` // "<framework> <control_id>" — the display-name key
	State         string `json:"state"`   // met | gap | exception
	Met           bool   `json:"met"`
	EvidenceCount int    `json:"evidence_count"`
	EvidenceURL   string `json:"evidence_url"`
	AssessedAt    string `json:"assessed_at"` // RFC 3339
	Source        string `json:"source"`
}

// Schema is the JSON schema Drata needs when the connection is created — the record shape above.
var Schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"id":             map[string]any{"type": "string"},
		"framework":      map[string]any{"type": "string"},
		"control_id":     map[string]any{"type": "string"},
		"control":        map[string]any{"type": "string"},
		"state":          map[string]any{"type": "string"},
		"met":            map[string]any{"type": "boolean"},
		"evidence_count": map[string]any{"type": "integer"},
		"evidence_url":   map[string]any{"type": "string"},
		"assessed_at":    map[string]any{"type": "string"},
		"source":         map[string]any{"type": "string"},
	},
	"additionalProperties": true,
}

// DisplayNameKey is the record property Drata labels rows with.
const DisplayNameKey = "control"

var idClean = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Records turns control states into rows, sorted for a deterministic push. evidenceBase is the
// app origin the evidence_url points into (the per-framework compliance page); source names who
// produced the row (the tenant's brand, so a white-labelled workspace's rows say so).
func Records(states []platform.ControlState, evidenceBase, source string) []Record {
	out := make([]Record, 0, len(states))
	for _, s := range states {
		if s.Framework == "" || s.ControlID == "" {
			continue
		}
		// State constants are already "met"/"gap"/"exception"; normalise anything unexpected to a
		// lower-cased form rather than inventing a verdict.
		st := strings.ToLower(strings.TrimSpace(s.State))
		r := Record{
			ID:            idClean.ReplaceAllString(s.Framework+"-"+s.ControlID, "_"),
			Framework:     s.Framework,
			ControlID:     s.ControlID,
			Control:       s.Framework + " " + s.ControlID,
			State:         st,
			Met:           s.State == platform.ControlMet,
			EvidenceCount: len(s.EvidenceRefs),
			Source:        source,
		}
		if evidenceBase != "" {
			r.EvidenceURL = strings.TrimRight(evidenceBase, "/") + "/compliance/" + s.Framework
		}
		if !s.UpdatedAt.IsZero() {
			r.AssessedAt = s.UpdatedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Client talks to Drata's public API. BaseURL defaults to the public endpoint; HTTP to a bounded
// client. The API key is a bearer token.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// ErrNoCredentials is returned when the client has no API key.
var ErrNoCredentials = errors.New("drata: no API key")

func (c *Client) base() string {
	if c.BaseURL == "" {
		return "https://public-api.drata.com"
	}
	return strings.TrimRight(c.BaseURL, "/")
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	if strings.TrimSpace(c.APIKey) == "" {
		return ErrNoCredentials
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("drata: %s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return fmt.Errorf("drata: %s %s: HTTP %d: %s", method, path, res.StatusCode, msg)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Connection identifies the custom connection + resource records are pushed into.
type Connection struct {
	ConnectionID int `json:"connection_id"`
	ResourceID   int `json:"resource_id"`
}

// EnsureConnection creates the custom connection (and its one resource) when the config has none,
// else returns it unchanged. Creating is the one call that changes Drata's configuration, so it is
// done once and the ids are stored on the tenant.
func (c *Client) EnsureConnection(ctx context.Context, have Connection, name string, workspaceID int) (Connection, error) {
	if have.ConnectionID > 0 && have.ResourceID > 0 {
		return have, nil
	}
	var created struct {
		ID              int `json:"id"`
		CustomResources []struct {
			ID int `json:"id"`
		} `json:"customResources"`
	}
	body := map[string]any{
		"name":           name,
		"providerTypes":  []string{"CUSTOM"},
		"workspaceIds":   []int{workspaceID},
		"displayNameKey": DisplayNameKey,
		"description":    "Control posture from the TensorShield engine: one row per framework control, met or gap, with the finding count and evidence link. Author a test over `met` and map it to the control.",
		"schema":         Schema,
	}
	if err := c.do(ctx, http.MethodPost, "/public/v2/custom-connections", body, &created); err != nil {
		return have, err
	}
	out := Connection{ConnectionID: created.ID}
	if len(created.CustomResources) > 0 {
		out.ResourceID = created.CustomResources[0].ID
	}
	if out.ResourceID == 0 {
		// The create response did not carry the resource; fetch it, as Drata's recipe does.
		var got struct {
			CustomResources []struct {
				ID int `json:"id"`
			} `json:"customResources"`
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/public/v2/custom-connections/%d?expand[]=customResources", out.ConnectionID), nil, &got); err != nil {
			return out, err
		}
		if len(got.CustomResources) == 0 {
			return out, errors.New("drata: connection created but it carries no custom resource")
		}
		out.ResourceID = got.CustomResources[0].ID
	}
	return out, nil
}

// PushResult is what a push actually did.
type PushResult struct {
	Records   int    `json:"records"`
	SessionID string `json:"session_id"`
	Replaced  bool   `json:"replaced"` // the session was completed: the previous batch is gone
}

// Push uploads the records as one session and completes it — an atomic full-state replace. An
// empty set is refused rather than pushed: completing an empty session would delete every row and
// read, in Drata, as "TensorShield reports nothing", which is not what "we assessed nothing" means.
func (c *Client) Push(ctx context.Context, conn Connection, records []Record, now time.Time) (PushResult, error) {
	if conn.ConnectionID == 0 || conn.ResourceID == 0 {
		return PushResult{}, errors.New("drata: no connection configured")
	}
	if len(records) == 0 {
		return PushResult{}, errors.New("drata: refusing to push an empty record set (it would erase the previous batch)")
	}
	session := "ts-" + now.UTC().Format("20060102-150405")
	base := fmt.Sprintf("/public/v2/custom-connections/%d/resources/%d/sessions/%s", conn.ConnectionID, conn.ResourceID, session)
	// batches of 500 to stay under any body limit; all in one session so completion is atomic
	for i := 0; i < len(records); i += 500 {
		end := i + 500
		if end > len(records) {
			end = len(records)
		}
		if err := c.do(ctx, http.MethodPost, base, map[string]any{"data": records[i:end]}, nil); err != nil {
			return PushResult{Records: i, SessionID: session}, err
		}
	}
	if err := c.do(ctx, http.MethodPost, base+"/actions", map[string]any{"action": "complete"}, nil); err != nil {
		return PushResult{Records: len(records), SessionID: session}, err
	}
	return PushResult{Records: len(records), SessionID: session, Replaced: true}, nil
}
