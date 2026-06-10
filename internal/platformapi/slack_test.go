package platformapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

const slackSecret = "s3cr3t-signing"

func slackHandler(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutAction(context.Background(), platform.Action{ID: "act1", TenantID: "t1", Tier: 2, Kind: platform.ActApplyConfig, Status: platform.ActPendingApproval})
	desk := &hitl.Desk{Store: st, Apply: noopApplier{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Desk: desk, Token: "tok", SlackSigningSecret: slackSecret})
	return h, st
}

// signedSlackReq builds a Slack interactive request with a valid v0 signature.
func signedSlackReq(payload string, ts int64) *http.Request {
	body := "payload=" + url.QueryEscape(payload)
	mac := hmac.New(sha256.New, []byte(slackSecret))
	mac.Write([]byte("v0:" + strconv.FormatInt(ts, 10) + ":" + body))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))
	req := httptest.NewRequest("POST", "/v1/slack/interactive", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Slack-Signature", sig)
	return req
}

func approvePayload() string {
	return `{"user":{"username":"kanpur-1"},"actions":[{"action_id":"approve","value":"t1:act1"}]}`
}

func TestSlackInteractive_ValidSignatureApproves(t *testing.T) {
	h, st := slackHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedSlackReq(approvePayload(), time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	got, _ := st.GetAction(context.Background(), "t1", "act1")
	if got.Status != platform.ActApplied {
		t.Errorf("a valid slack approve should apply the action, got %s", got.Status)
	}
	if got.Approver != "slack:kanpur-1" {
		t.Errorf("approver should be recorded from slack user, got %q", got.Approver)
	}
}

func TestSlackInteractive_ForgedSignatureRejected(t *testing.T) {
	h, st := slackHandler(t)
	req := signedSlackReq(approvePayload(), time.Now().Unix())
	req.Header.Set("X-Slack-Signature", "v0="+strings.Repeat("0", 64)) // wrong sig
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a forged signature must be 401, got %d", rec.Code)
	}
	// the action must NOT have been approved
	got, _ := st.GetAction(context.Background(), "t1", "act1")
	if got.Status != platform.ActPendingApproval {
		t.Errorf("a forged callback must not change the action, status=%s", got.Status)
	}
}

func TestSlackInteractive_StaleTimestampRejected(t *testing.T) {
	h, _ := slackHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedSlackReq(approvePayload(), time.Now().Add(-10*time.Minute).Unix()))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a stale (replayed) timestamp must be 401, got %d", rec.Code)
	}
}

func TestSlackInteractive_NotConfigured(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "tok"}) // no Desk/secret
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedSlackReq(approvePayload(), time.Now().Unix()))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("unconfigured slack endpoint should be 501, got %d", rec.Code)
	}
}
