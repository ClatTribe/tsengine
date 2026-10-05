package runner

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// eventFindingID is the identity of a finding derived from LOG EVENTS (CloudTrail, identity-provider
// audit logs). Every read re-reads a one-hour overlap so a late-delivered event is not skipped, which
// means the same event is read on several consecutive polls; with a random id each read stored it again,
// and polling every few minutes would have turned one root login into a dozen findings.
//
// The id is derived from what the finding IS: the provider's own event id when the source gives one,
// else the rule, the subject and the description (which names the actor, source and time). Re-reading
// the same event produces the same id, so the store updates rather than duplicates.
func eventFindingID(prefix string, f types.Finding) string {
	key := f.RuleID + "|" + f.Endpoint + "|"
	if id := f.ToolArgs["event_id"]; id != "" {
		key += "event:" + id
	} else {
		key += f.Description
	}
	sum := sha256.Sum256([]byte(key))
	return prefix + "-" + hex.EncodeToString(sum[:10])
}
