package platformapi

import (
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// apikey_scope.go is what a MACHINE credential may reach. Closed by default, like the employee seat:
// a route added later is out of reach for every key until somebody deliberately names it here, and
// whoever adds a route has no reason to be thinking about CI keys.
//
// There is deliberately no scope that DECIDES anything. Approving a fix, accepting a risk, publishing a
// policy, halting or resuming automation, changing a setting, minting another key — each requires a
// named human (§18.4), and a key is not one. The worst a leaked ingest key can do is post data into the
// workspace it belongs to; the worst a leaked read key can do is read it.

// ingestRoutes are the calls a pipeline or a collector makes: post scan output, inventories and
// events, run the PR check, start a scan and poll it. Paths use the mux's {name} wildcard.
var ingestRoutes = []struct {
	method, path string
}{
	{http.MethodPost, "/v1/ci/pr-check"},              // the merge gate in CI
	{http.MethodPost, "/v1/import"},                   // an existing SARIF / Snyk / Dependabot backlog
	{http.MethodPost, "/v1/import/postman"},           // an API collection as scan scope
	{http.MethodPost, "/v1/rescan"},                   // scan on deploy
	{http.MethodGet, "/v1/jobs/{id}"},                 // poll the scan it started
	{http.MethodPost, "/v1/cloud/inventory"},          // posted cloud state
	{http.MethodPost, "/v1/cloud/events"},             // a CloudTrail / audit-log forwarder
	{http.MethodPost, "/v1/osint/ingest"},             // an OSINT collector's snapshot
	{http.MethodPost, "/v1/devices/ingest"},           // an MDM export
	{http.MethodPost, "/v1/identity/events"},          // an IdP audit-log forwarder
	{http.MethodPost, "/v1/runtime/events"},           // a runtime sensor
	{http.MethodPost, "/v1/control-plane/detections"}, // WAF logs for detection validation
	{http.MethodPost, "/v1/tprm/ingest"},              // a procurement system's vendor list
	{http.MethodPost, "/v1/dataplatform/ingest"},      // a warehouse grant export
	{http.MethodPost, "/v1/saas/{provider}/snapshot"}, // a SaaS posture snapshot
	{http.MethodPost, "/v1/scuba/ingest"},             // the customer's own ScubaGear run
	{http.MethodPost, "/v1/registry/reconcile"},       // a registry watcher (scan on push)
	{http.MethodPost, "/v1/vercel/ingest"},            // deployment-platform posture
	{http.MethodPost, "/v1/agents/ingest"},            // AI-agent estate posture
	{http.MethodPost, "/v1/agents/telemetry"},         // AI-agent telemetry
}

// apiKeyMayReach reports whether a key carrying these scopes may make this request.
//
// read reaches every GET/HEAD an app member could make (routes behind the shared auth gate); ingest
// reaches exactly ingestRoutes. A key with both reaches the union. Nothing else, for any key.
func apiKeyMayReach(k platform.APIKey, method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	if k.HasScope(platform.APIKeyScopeRead) && (method == http.MethodGet || method == http.MethodHead) {
		return true
	}
	if k.HasScope(platform.APIKeyScopeIngest) {
		for _, a := range ingestRoutes {
			if a.method == method && pathMatches(a.path, path) {
				return true
			}
		}
	}
	return false
}
