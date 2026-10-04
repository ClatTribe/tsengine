package notify

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ownerText is the routing line every channel renders, in plain words. ok=false when the incident was not
// tied to an asset — then nothing is said, because "we do not know which asset" is not "nobody owns it".
// An asset with no owner says so, since a page with no route to a person is the gap someone has to close.
func ownerText(inc platform.Incident) (string, bool) {
	if inc.AssetID == "" {
		return "", false
	}
	switch o, t := strings.TrimSpace(inc.Owner), strings.TrimSpace(inc.Team); {
	case o != "" && t != "":
		return o + " (" + t + ")", true
	case o != "":
		return o, true
	case t != "":
		return t, true
	}
	return "unassigned — nobody is recorded as owning " + nz(inc.AssetTarget, "this asset") + "; set an owner on the asset", true
}

// slackOwner is ownerText with an @mention when the owner's Slack member id is known. An incoming webhook
// resolves <@U…> and nothing else, so the mention is only emitted from a validated member id.
func slackOwner(inc platform.Incident) (string, bool) {
	txt, ok := ownerText(inc)
	if !ok {
		return "", false
	}
	if inc.OwnerSlackID != "" {
		return "<@" + inc.OwnerSlackID + "> (" + txt + ")", true
	}
	return txt, true
}
