package platformapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/hitl"
)

// handleSlackInteractive receives Slack Block Kit button clicks (Approve/Reject on a
// queued action) and drives the HITL decision. Slack POSTs a signed,
// form-urlencoded body with a `payload` JSON field; we verify the v0 signature
// (HMAC-SHA256 over "v0:<ts>:<rawBody>") against SlackSigningSecret before acting —
// so a forged callback can never approve a remediation.
func (d Deps) handleSlackInteractive(w http.ResponseWriter, r *http.Request) {
	if d.Desk == nil || d.SlackSigningSecret == "" {
		writeJSON(w, http.StatusNotImplemented, errBody("slack approvals not configured"))
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if !verifySlackSig(d.SlackSigningSecret, r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature"), raw) {
		writeJSON(w, http.StatusUnauthorized, errBody("bad slack signature"))
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad form"))
		return
	}
	var p slackPayload
	if err := json.Unmarshal([]byte(form.Get("payload")), &p); err != nil || len(p.Actions) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("bad payload"))
		return
	}
	act := p.Actions[0]
	tenantID, actionID, ok := strings.Cut(act.Value, ":")
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("bad action value"))
		return
	}
	approver := firstNonEmpty(p.User.Username, p.User.Name, p.User.ID, "slack")
	verdict := hitl.Verdict{Approver: "slack:" + approver, Approve: act.ActionID == "approve"}
	decided, derr := d.Desk.Decide(r.Context(), tenantID, actionID, verdict)
	if derr != nil {
		// reply in-channel so the analyst sees why (Slack shows replace_original text)
		writeJSON(w, http.StatusOK, map[string]any{"text": "⚠️ " + derr.Error(), "replace_original": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"replace_original": true,
		"text":             fmt.Sprintf("✅ %s → *%s* by %s", actionID, decided.Status, verdict.Approver),
	})
}

// verifySlackSig validates Slack's v0 request signature and rejects stale timestamps.
func verifySlackSig(secret, tsHeader, sigHeader string, body []byte) bool {
	if secret == "" || tsHeader == "" || !strings.HasPrefix(sigHeader, "v0=") {
		return false
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil || absInt64(timeNow().Unix()-ts) > 300 { // 5-minute replay window
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsHeader + ":"))
	mac.Write(body)
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sigHeader))
}

// timeNow is swappable in tests (Slack signing checks the timestamp).
var timeNow = time.Now

type slackPayload struct {
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	} `json:"user"`
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
