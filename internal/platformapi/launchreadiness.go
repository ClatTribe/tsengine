package platformapi

import (
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector"
)

// GET /v1/launch-readiness — operator-token gated. The DEPLOYMENT half of the pre-outreach check.
//
// scripts/launch-check.sh reads the deployed SITE: the addresses in security.txt, the footer, the
// entry points outreach links to. It cannot see the things that fail silently INSIDE the process:
// a lead form whose delivery is a log line because TSENGINE_SALES_EMAIL is unset, a "Connect
// GitHub" button that 302s to an OAuth app nobody registered, an AI engineer with no operator
// model behind it, password-reset mail with no SMTP. Every one of those has a happy status page in
// front of it. This endpoint reports each as a fact read from the running configuration — never
// inferred from a request that happened to succeed — with the environment variable that fixes it,
// so the launch check can name what nobody set instead of the outreach discovering it.
//
// It reports what IS configured, not whether it WORKS: a set SMTP host is not a delivered email.
// The verdict says so.

type readinessItem struct {
	Key      string `json:"key"`
	OK       bool   `json:"ok"`
	Blocking bool   `json:"blocking"` // false = worth knowing, not a reason to hold outreach
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
}

type readinessView struct {
	Ready    bool            `json:"ready"` // every blocking item ok
	Items    []readinessItem `json:"items"`
	Blocking []string        `json:"blocking,omitempty"` // keys of failing blocking items
	Caveat   string          `json:"caveat"`
}

func (d Deps) launchReadiness() readinessView {
	var items []readinessItem
	add := func(key string, ok, blocking bool, detail, fix string) {
		if ok {
			fix = ""
		}
		items = append(items, readinessItem{Key: key, OK: ok, Blocking: blocking, Detail: detail, Fix: fix})
	}

	mailOK := d.Mailer != nil && d.Mailer.Configured()
	add("transactional_email", mailOK, true,
		ternary(mailOK, "a mailer is configured (password reset, invites, first-findings email)", "no mailer — password reset and the first-findings email cannot send; the invite temp password shows in the UI instead"),
		"set SMTP_HOST / SMTP_USER / SMTP_PASS / SMTP_FROM")

	sales := strings.TrimSpace(os.Getenv("TSENGINE_SALES_EMAIL"))
	leadOK := sales != "" && mailOK
	add("sales_lead_delivery", leadOK, true,
		ternary(leadOK, "leads from /scan, the SOC 2 assessment, the demo form and signups are emailed to "+sales,
			ternary(sales == "", "TSENGINE_SALES_EMAIL is unset — every lead stops at a log line", "TSENGINE_SALES_EMAIL is set but no mailer is configured — leads stop at a log line")),
		"set TSENGINE_SALES_EMAIL (and SMTP_*)")

	// OAuth connectors: the "Connect" buttons. An unconfigured connector renders a dead door.
	var configured, missing []string
	if d.Connectors != nil {
		for _, k := range d.Connectors.Kinds() {
			c, err := d.Connectors.Get(k)
			if err != nil {
				continue
			}
			if connector.IsConfigured(c) {
				configured = append(configured, k)
			} else {
				missing = append(missing, k)
			}
		}
	}
	sort.Strings(configured)
	sort.Strings(missing)
	connOK := len(configured) > 0
	add("oauth_connectors", connOK, true,
		ternary(connOK, "configured: "+strings.Join(configured, ", ")+ternary(len(missing) > 0, " · not configured: "+strings.Join(missing, ", "), ""),
			"no connector has its OAuth app credentials — every Connect button is a dead door"),
		"register the OAuth apps and set each provider's *_CLIENT_ID / *_CLIENT_SECRET (see docs/platform-operations.md)")

	llmOK := d.AgentLLM != nil
	add("operator_llm", llmOK, false,
		ternary(llmOK, "an operator model is configured — Core-plan tenants get the AI engineer without a key of their own",
			"no operator model — the AI engineer runs only for tenants who bring their own key (Free is unaffected by design)"),
		"set ANTHROPIC_API_KEY or LLM_API_KEY (+ LLM_BASE_URL for a compatible endpoint)")

	corpus := strings.TrimSpace(os.Getenv("TSENGINE_THREAT_INTEL_CORPUS"))
	corpusOK := false
	if corpus != "" {
		if st, err := os.Stat(corpus); err == nil && !st.IsDir() && st.Size() > 0 {
			corpusOK = true
		}
	}
	add("threat_intel_corpus", corpusOK, false,
		ternary(corpusOK, "refreshed KEV/EPSS corpus at "+corpus,
			ternary(corpus == "", "TSENGINE_THREAT_INTEL_CORPUS is unset — findings are enriched from the small embedded snapshot, not a refreshed feed", "TSENGINE_THREAT_INTEL_CORPUS is set but the file is missing or empty — the embedded snapshot is used")),
		"set TSENGINE_THREAT_INTEL_CORPUS to a corpus file and run `tsengine corpus refresh` (or let the in-process refresher populate it)")

	urlsOK := strings.HasPrefix(d.PublicURL, "https://") && strings.HasPrefix(d.AppURL, "https://")
	add("public_urls", urlsOK, true,
		ternary(urlsOK, "PublicURL "+d.PublicURL+" · AppURL "+d.AppURL,
			"PublicURL/AppURL are not both https — OAuth redirect_uri and the post-connect redirect will be wrong: PublicURL="+d.PublicURL+" AppURL="+d.AppURL),
		"set TSENGINE_PLATFORM_PUBLIC (the API origin) and TSENGINE_APP_URL (the app origin) to https URLs")

	v := readinessView{Items: items, Ready: true,
		Caveat: "reports what is CONFIGURED, read from the running process — not that it works: a set SMTP host is not a delivered email. Pair with scripts/launch-check.sh, which reads the deployed site."}
	for _, it := range items {
		if it.Blocking && !it.OK {
			v.Ready = false
			v.Blocking = append(v.Blocking, it.Key)
		}
	}
	return v
}

func (d Deps) handleLaunchReadiness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.launchReadiness())
}
