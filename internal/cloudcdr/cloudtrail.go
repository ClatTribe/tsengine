package cloudcdr

import (
	"encoding/json"
	"strings"
)

// FromCloudTrail normalises one CloudTrail record (the JSON the LookupEvents API returns as
// CloudTrailEvent, or a record from a trail's log file) into the Event the rules classify.
//
// THE GAP THIS CLOSES. The CDR rules existed and accepted only POSTED events — a customer-built
// forwarder nobody built — so a root console login or a trail being stopped opened an incident only
// if someone else's pipeline told us. The poller (awsfetch.CloudTrailLister) reads the account's own
// 90-day event history through the connected read-only role; this is the translation.
//
// What is carried and why: the ACTOR is "root" for the root identity (the rule keys on it) and
// otherwise the ARN or user name CloudTrail names; the RESOURCE is the first resource ARN CloudTrail
// attributes, else the identifier the request parameters name (bucket, security group, user, role,
// policy, trail); the DETAIL is the request parameters serialised compactly, because the rules look
// for the VALUES that make an action dangerous (0.0.0.0/0, AllUsers, AdministratorAccess, "*") and
// those live there. An unparseable record is dropped and counted by the caller, never guessed at.
func FromCloudTrail(raw []byte) (Event, bool) {
	var rec struct {
		EventName    string          `json:"eventName"`
		EventSource  string          `json:"eventSource"`
		AWSRegion    string          `json:"awsRegion"`
		SourceIP     string          `json:"sourceIPAddress"`
		UserIdentity json.RawMessage `json:"userIdentity"`
		Params       json.RawMessage `json:"requestParameters"`
		Resources    []struct {
			ARN  string `json:"ARN"`
			Type string `json:"type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil || strings.TrimSpace(rec.EventName) == "" {
		return Event{}, false
	}
	ev := Event{Provider: "aws", EventName: rec.EventName, SourceIP: rec.SourceIP, Region: rec.AWSRegion}

	var ui struct {
		Type     string `json:"type"`
		ARN      string `json:"arn"`
		UserName string `json:"userName"`
		Session  struct {
			Issuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	}
	_ = json.Unmarshal(rec.UserIdentity, &ui)
	switch {
	case strings.EqualFold(ui.Type, "Root"):
		ev.Actor = "root"
	case ui.ARN != "":
		ev.Actor = ui.ARN
	case ui.Session.Issuer.ARN != "":
		ev.Actor = ui.Session.Issuer.ARN
	default:
		ev.Actor = ui.UserName
	}

	var params map[string]any
	_ = json.Unmarshal(rec.Params, &params)
	if len(rec.Resources) > 0 && rec.Resources[0].ARN != "" {
		ev.Resource = rec.Resources[0].ARN
	} else {
		for _, k := range []string{"bucketName", "groupId", "groupName", "userName", "roleName", "policyArn", "name", "trailName", "functionName", "dBInstanceIdentifier"} {
			if v, ok := params[k].(string); ok && v != "" {
				ev.Resource = v
				break
			}
		}
	}
	if len(rec.Params) > 0 && string(rec.Params) != "null" {
		if b, err := json.Marshal(params); err == nil {
			ev.Detail = string(b)
		} else {
			ev.Detail = string(rec.Params)
		}
	}
	return ev, true
}

// FromCloudTrailBatch normalises many records, returning the events and how many records could not
// be read — the caller reports the count rather than letting an unreadable batch read as a quiet one.
func FromCloudTrailBatch(raws [][]byte) ([]Event, int) {
	var out []Event
	dropped := 0
	for _, r := range raws {
		if ev, ok := FromCloudTrail(r); ok {
			out = append(out, ev)
		} else {
			dropped++
		}
	}
	return out, dropped
}
