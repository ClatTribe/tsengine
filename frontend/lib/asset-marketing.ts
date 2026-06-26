// Content map for the per-asset marketing pages (the asset-intent SEO surface). One entry per asset type,
// grounded in the real anchor tools (lib/assets.ts) + the frameworks each asset's findings map to. A thin
// page file under app/(marketing)/<slug>/ renders <AssetMarketingPage data={ASSET_PAGES.<key>} />.
//
// Two-GTM framing is shared in the component footer (self-serve / managed / MSP), not duplicated per asset.

export type AssetCheck = { t: string; d: string };
export type AssetFaq = { q: string; a: string };

export type AssetPage = {
  slug: string; // SEO route, e.g. "cloud-security"
  icon: string; // FeatureIcon name
  eyebrow: string; // hero badge
  h1: string;
  sub: string;
  ctaPrimary: string;
  checks: AssetCheck[]; // what it assesses
  tools: string[]; // lead OSS tools wrapped (the "best-in-class OSS, not in-house" story)
  how: AssetCheck[]; // 3-step "how it works"
  frameworks: string; // which compliance controls/frameworks the findings map to
  faq: AssetFaq[];
  seoTitle: string;
  seoDesc: string;
};

export const ASSET_PAGES: Record<string, AssetPage> = {
  cloud: {
    slug: "cloud-security",
    icon: "cloud",
    eyebrow: "Cloud security (CSPM + CIEM)",
    h1: "Find the cloud path an attacker would actually take.",
    sub: "Connect AWS, GCP, or Azure read-only and we map your real posture — public buckets, over-privileged IAM, exposed services — then trace the attack paths that chain a misconfig to your crown-jewel data. Grounded in the live account, never a generic checklist.",
    ctaPrimary: "Connect a cloud account",
    checks: [
      { t: "CIS posture, multi-cloud", d: "AWS/GCP/Azure benchmark checks — encryption, logging, public exposure, network segmentation — scored against the live account." },
      { t: "IAM attack paths (CIEM)", d: "Effective-permission analysis that finds the role chain reaching sensitive data, not just one bad policy in isolation." },
      { t: "Data exposure (DSPM)", d: "Sensitive data sitting in a public bucket or an unencrypted store, prioritized by blast radius." },
      { t: "Live, HITL remediation", d: "Block-public-access and storage hardening apply through a scoped write role — only after a human approves." },
    ],
    tools: ["prowler", "scout-suite"],
    how: [
      { t: "Connect read-only", d: "A scoped SecurityAudit/read role — no standing write access. We never mutate without an approval." },
      { t: "Map + correlate", d: "Findings become attack paths: a public key → an IAM role → customer data, each step backed by a tool result." },
      { t: "Fix on approval", d: "Each fix is re-checked (does it cut the path?) and applied through the gated write path, signed into the ledger." },
    ],
    frameworks: "Cloud findings map to SOC 2 (CC6.x), PCI-DSS (1.x/3.x), HIPAA (164.312), NIST 800-53 (SC-7/SC-28/AC-6), CIS Controls, and FedRAMP — only where a real control nexus exists.",
    faq: [
      { q: "Do you need write access to my cloud?", a: "No — scanning is read-only (a scoped SecurityAudit role). A live fix uses a separate, opt-in write role and only runs after a named human approves it at the HITL desk." },
      { q: "How is this different from Prowler or Scout Suite?", a: "We wrap those best-in-class OSS scanners, then add what they don't: cross-resource attack-path correlation (CIEM), data-tier prioritization (DSPM), and a human-gated remediation loop." },
      { q: "Is a clean scan a compliance certification?", a: "No. We map findings to controls but never mark a control compliant from a scan — an independent auditor attests. We make you audit-ready, honestly." },
    ],
    seoTitle: "Cloud Security (CSPM + CIEM) for AWS, GCP & Azure | TensorShield",
    seoDesc: "Agentless cloud security: CIS posture, IAM attack paths, and data exposure across AWS/GCP/Azure — with human-gated remediation. Grounded in your live account, never a generic checklist.",
  },
  api: {
    slug: "api-security",
    icon: "network",
    eyebrow: "API security",
    h1: "Test the API the way an attacker reads the spec.",
    sub: "Point us at a REST, GraphQL, or gRPC API and we ingest its OpenAPI spec, map every operation, then fuzz each one and hunt shadow routes. The deep business-logic flaws — BOLA/BFLA — get a differential authz test that proves the bypass, never guesses it.",
    ctaPrimary: "Scan an API",
    checks: [
      { t: "Spec-driven fuzzing", d: "OpenAPI ingest → schemathesis + nuclei across every operation — injection, auth, conformance, mass-assignment." },
      { t: "Shadow-route discovery", d: "kiterunner finds the undocumented endpoints that aren't in the spec but are live." },
      { t: "BOLA / BFLA, proven", d: "A differential authz test replays the victim's request as the attacker — a hit is verified (2xx with victim data), never a guess." },
      { t: "GraphQL aware", d: "Introspection + per-resolver checks for the queries that leak data or escalate." },
    ],
    tools: ["nuclei", "kiterunner", "schemathesis"],
    how: [
      { t: "Ingest the spec", d: "OpenAPI/Swagger → the exact operation inventory becomes the scan surface (no blind crawling)." },
      { t: "Fan out per method", d: "Each operation gets the right tool — spec fuzz, injection, shadow-route brute — run in the sandbox." },
      { t: "Prove authz logic", d: "The consent-gated apiauthz prober demonstrates BOLA/BFLA with two real identities, so a finding is exploitation-proven." },
    ],
    frameworks: "API findings map to OWASP API Top 10, SOC 2 (CC6.1), and PCI-DSS (6.2.4) where a control nexus exists.",
    faq: [
      { q: "Do you need the OpenAPI spec?", a: "It's ideal — the spec gives the exact operation inventory for precise, low-noise fuzzing. Without one we fall back to crawling the base URL." },
      { q: "Can you find BOLA/BFLA (broken object/function-level authorization)?", a: "Yes — that's the differential authz test: it replays one identity's request as another and flags a bypass only on proven access to the victim's data, so the finding is verified." },
      { q: "Is active testing safe?", a: "The active prober is consent-gated and benign-by-construction (canary probes, true/false differentials that extract no data). You authorize it per engagement." },
    ],
    seoTitle: "API Security Testing — REST, GraphQL & BOLA/BFLA | TensorShield",
    seoDesc: "Spec-driven API security: OpenAPI ingest, per-operation fuzzing, shadow-route discovery, and a differential BOLA/BFLA authz test that proves the bypass. Grounded, low-noise.",
  },
  container: {
    slug: "container-security",
    icon: "layers",
    eyebrow: "Container & image security",
    h1: "Know what's in your image before it ships.",
    sub: "Scan any container image for CVEs, misconfigurations, and a full SBOM — corroborated across two independent scanners so a real vulnerability stands out from the noise. Scan-on-push keeps every new image checked automatically.",
    ctaPrimary: "Scan an image",
    checks: [
      { t: "Image CVEs, corroborated", d: "trivy + grype both run; a vuln both agree on is high-confidence, the rest is triaged down." },
      { t: "Misconfiguration", d: "dockle flags Dockerfile + image hardening gaps — root user, missing healthcheck, secrets baked in." },
      { t: "SBOM", d: "A full software bill of materials (syft) for every image — the inventory auditors and incident response need." },
      { t: "Scan-on-push", d: "A registry digest-diff scans only new or re-pushed images, so coverage stays current without re-scanning everything." },
    ],
    tools: ["trivy", "grype", "dockle"],
    how: [
      { t: "Point at the image", d: "A registry ref or a local image — the scanners pull and inspect it inside the hardened sandbox." },
      { t: "Corroborate", d: "Two SCA engines run; agreement raises confidence, single-tool hits are flagged 'confirm', never dressed as proven." },
      { t: "Fix the base", d: "Remediation targets the base image / package coordinate, with the upgrade that clears the most CVEs at once." },
    ],
    frameworks: "Image findings map to SOC 2 (CC7.1), PCI-DSS (6.3.x), and CIS Docker/Kubernetes benchmarks where applicable.",
    faq: [
      { q: "Which scanners do you use?", a: "trivy and grype for CVEs (corroborated), dockle for misconfig, and syft for the SBOM — all best-in-class OSS, run together so one tool's miss is another's catch." },
      { q: "Can you scan on every push?", a: "Yes — a registry connector digest-diffs against last-seen and scans only new or changed images, so you're not re-scanning the unchanged set." },
      { q: "Do you reduce false positives?", a: "Corroboration is the FP control: a CVE both scanners report is high-confidence; a single-tool hit is shown as needing confirmation, never as proven." },
    ],
    seoTitle: "Container & Image Security — CVEs, Misconfig & SBOM | TensorShield",
    seoDesc: "Container image scanning with corroborated CVEs (trivy + grype), Dockerfile misconfiguration checks, full SBOM, and scan-on-push. Low false positives by design.",
  },
  mobile: {
    slug: "mobile-app-security",
    icon: "shield",
    eyebrow: "Mobile app security",
    h1: "Ship the app without shipping the keys.",
    sub: "Scan your Android (APK/source) or iOS (IPA/source) bundle for insecure storage, weak crypto, and hardcoded secrets — the mobile flaws that leak user data and API keys. The bundle is the surface; no device farm required.",
    ctaPrimary: "Scan a mobile app",
    checks: [
      { t: "Mobile SAST", d: "mobsfscan flags insecure storage, weak/disabled crypto, exported components, and unsafe WebView config." },
      { t: "Hardcoded secrets", d: "gitleaks finds API keys, tokens, and credentials baked into the bundle or source." },
      { t: "Bundled-dependency CVEs", d: "trivy fs scans the app's third-party libraries for known vulnerabilities." },
      { t: "Grounded, low-noise", d: "A hardened bundle yields zero findings — every flag cites the offending file and line." },
    ],
    tools: ["mobsfscan", "gitleaks", "trivy"],
    how: [
      { t: "Upload the bundle", d: "An APK/IPA or the source tree — it's the whole surface, mounted read-only in the sandbox." },
      { t: "Run mobile SAST + secrets", d: "mobsfscan + gitleaks + trivy fs fan out across the bundle in one pass." },
      { t: "Fix with file:line", d: "Each finding names the exact file and line, so the fix is a code change, not a treasure hunt." },
    ],
    frameworks: "Mobile findings map to OWASP MASVS, SOC 2 (CC6.1/CC6.7), and HIPAA (164.312) where user data is handled.",
    faq: [
      { q: "Do you need the source or the built app?", a: "Either — an APK/IPA bundle or the source tree. The bundle is the whole surface, so a built artifact is enough to find storage, crypto, and secret issues." },
      { q: "Android and iOS both?", a: "Yes — Android (APK/source) and iOS (IPA/source). The same mobile-SAST + secrets + bundled-dep-CVE pass runs across both." },
      { q: "Is this dynamic (running-app) testing?", a: "It's static analysis of the bundle today (no device farm needed) — the highest-ROI mobile coverage; runtime/DAST is a documented next step." },
    ],
    seoTitle: "Mobile App Security — Android & iOS SAST + Secrets | TensorShield",
    seoDesc: "Mobile app security testing for Android (APK) & iOS (IPA): insecure storage, weak crypto, hardcoded secrets, and bundled-dependency CVEs. The bundle is the surface — no device farm.",
  },
  web: {
    slug: "web-application-security",
    icon: "globe",
    eyebrow: "Web application security (DAST)",
    h1: "Crawl it, then break it — the way an attacker would.",
    sub: "We crawl your web app to map every real page and parameter, then fan injection, XSS, SSRF, and auth tests across the surface — with WordPress/CMS-specific depth where it matters. Authenticated scanning that actually stays logged in.",
    ctaPrimary: "Scan a web app",
    checks: [
      { t: "Full DAST", d: "Injection (SQLi), XSS, SSRF, open redirect, and auth flaws — nuclei + sqlmap + dalfox across the crawled surface." },
      { t: "Authenticated scanning", d: "A login flow that validates the session each scan, so you're never silently testing a logged-out app." },
      { t: "CMS depth", d: "WordPress/CMS surfaces get wpscan — vulnerable plugins/themes, user enumeration, exposed config." },
      { t: "Content discovery", d: "ffuf finds the unlinked endpoints a crawl alone would miss." },
    ],
    tools: ["nuclei", "sqlmap", "dalfox", "wpscan"],
    how: [
      { t: "Crawl the surface", d: "katana maps real pages + parameters; static assets and destructive paths are filtered out before any test fires." },
      { t: "Fan out by shape", d: "List-mode tools run once over the whole surface; injection tools run per param-bearing URL — no WAVSEP 2h trap." },
      { t: "Confirm + fix", d: "A finding is corroborated across tools and re-fired to verify before it's surfaced — low false positives." },
    ],
    frameworks: "Web findings map to OWASP Top 10, SOC 2 (CC6.1), PCI-DSS (6.2.4), and GDPR Art. 32 where a control nexus exists.",
    faq: [
      { q: "Can it scan behind a login?", a: "Yes — you configure a login flow (form/token/recorded) and we validate the session each scan and re-auth on expiry, so the scan never silently runs logged-out." },
      { q: "Will it break my site?", a: "No — destructive paths are filtered before testing, list-mode tools are scoped, and the scan respects your timeout. It's a safe, bounded DAST." },
      { q: "Does it handle WordPress?", a: "Yes — a WordPress/CMS surface triggers wpscan for vulnerable plugins/themes, user enumeration, and exposed wp-config." },
    ],
    seoTitle: "Web Application Security Testing (DAST) | TensorShield",
    seoDesc: "Web app DAST: crawl-then-fuzz for SQLi, XSS, SSRF, auth flaws, and WordPress/CMS issues — with reliable authenticated scanning. Grounded, corroborated, low false positives.",
  },
  code: {
    slug: "code-security",
    icon: "git",
    eyebrow: "Code security (SAST + SCA)",
    h1: "Find the bug in your code and the CVE in your dependencies.",
    sub: "Connect GitHub or GitLab and we run SAST on your code, SCA with reachability on your dependencies, and secret scanning across history — then open a fix as an inline PR review, gated on the severity you set.",
    ctaPrimary: "Connect a repo",
    checks: [
      { t: "SAST (taint analysis)", d: "semgrep finds injection, deserialization, and auth flaws; an injection hit escalates to CodeQL taint on that language." },
      { t: "SCA with reachability", d: "Dependency CVEs filtered by whether the vulnerable code is actually reachable (govulncheck) — less noise, real risk." },
      { t: "Secret scanning", d: "gitleaks + trufflehog across the tree and history; a verified secret is flagged live." },
      { t: "Supply-chain risk", d: "Malicious packages, end-of-life runtimes, abandoned packages, and copyleft license risk — beyond just CVEs." },
    ],
    tools: ["semgrep", "govulncheck", "gitleaks", "trivy"],
    how: [
      { t: "Connect the repo", d: "GitHub/GitLab read access — we enumerate every repo and keep scanning on push." },
      { t: "Scan + reach", d: "SAST + SCA + secrets run; reachability prunes the dependency CVEs you can't actually trigger." },
      { t: "Fix in a PR", d: "A merge-gating PR-review bot comments inline on changed lines and a check-run blocks at your severity floor." },
    ],
    frameworks: "Code findings map to SOC 2 (CC7.1/CC8.1), PCI-DSS (6.x), and change-management controls where a nexus exists.",
    faq: [
      { q: "SAST and dependency scanning both?", a: "Yes — semgrep/CodeQL for your code, trivy/govulncheck for dependencies (with reachability), and gitleaks/trufflehog for secrets, in one pass per repo." },
      { q: "Does it block bad PRs?", a: "Optionally — the PR-review bot comments inline on changed lines and posts a check-run that fails at the severity floor you set, so risky changes don't merge silently." },
      { q: "What is reachability?", a: "A dependency CVE only matters if your code calls the vulnerable function. govulncheck filters out the CVEs in code paths you never reach, cutting the noise." },
    ],
    seoTitle: "Code Security — SAST, SCA with Reachability & Secrets | TensorShield",
    seoDesc: "Code security for GitHub/GitLab: SAST taint analysis, dependency CVEs with reachability, secret scanning, and merge-gating PR reviews. Real risk, less noise.",
  },
  network: {
    slug: "network-security",
    icon: "network",
    eyebrow: "Network & IP security",
    h1: "See what's exposed on your IPs before someone else does.",
    sub: "Give us an IP, CIDR, or range and we discover open ports and running services, then route the right vulnerability templates per port — so a dated SSH or an exposed database surfaces fast, with an upgrade path.",
    ctaPrimary: "Scan an IP range",
    checks: [
      { t: "Port + service discovery", d: "naabu + nmap map open ports and fingerprint the service and version on each." },
      { t: "Per-port vuln templates", d: "nuclei runs the templates that match each discovered service — ~50× faster than blanket scanning." },
      { t: "Outdated-service flagging", d: "A service running below its minimum-safe version (SSH, web servers, databases) is bumped and flagged with upgrade guidance." },
      { t: "Default-credential checks", d: "An open auth port (SSH, DB) gets a careful default-credential check for the obvious foothold." },
    ],
    tools: ["nmap", "naabu", "nuclei"],
    how: [
      { t: "Discover the surface", d: "naabu finds open ports across the range; nmap fingerprints the service + version on each." },
      { t: "Route by port", d: "Each port's service triggers only the matching vuln templates — fast and low-noise, not the whole corpus everywhere." },
      { t: "Flag + guide", d: "Outdated or default-credentialed services are surfaced with the concrete upgrade or hardening step." },
    ],
    frameworks: "Network findings map to SOC 2 (CC6.6/CC7.1), PCI-DSS (1.x/2.x), and CIS Controls where a nexus exists.",
    faq: [
      { q: "What do you scan — a single IP or a range?", a: "An IP, a CIDR, or a range. Port discovery runs across the whole set and per-port vuln templates route to each discovered service." },
      { q: "Is it slow?", a: "No — instead of running every template against every port, each port's fingerprinted service triggers only the matching templates, which is roughly 50× faster than a blanket scan." },
      { q: "Will it find outdated services?", a: "Yes — a service below its minimum-safe version (e.g. an old OpenSSH or web server) is bumped above info and flagged with upgrade guidance, grounded in the real version nmap detected." },
    ],
    seoTitle: "Network & IP Security Scanning — Ports, Services & CVEs | TensorShield",
    seoDesc: "Network security scanning for IPs/CIDRs: port + service discovery, per-port vulnerability templates, outdated-service flagging, and default-credential checks. Fast and low-noise.",
  },
  dns: {
    slug: "dns-domain-security",
    icon: "globe",
    eyebrow: "Domain & DNS security",
    h1: "Map your real internet footprint — and lock it down.",
    sub: "Enumerate every subdomain, catch dangling records ripe for takeover, and check your email-spoofing posture (DMARC/SPF/DKIM). The attacker's-eye view of your domain, turned into a fix list.",
    ctaPrimary: "Scan a domain",
    checks: [
      { t: "Subdomain enumeration", d: "subfinder + amass + Certificate Transparency map every subdomain — including the ones you forgot." },
      { t: "Subdomain takeover", d: "Dangling DNS records pointing at deprovisioned services — the classic, high-impact hijack — are flagged." },
      { t: "Email spoofing posture", d: "DMARC/SPF/DKIM checked from public DNS, so phishing-enabling gaps are caught with the exact record to publish." },
      { t: "Look-alike domains", d: "dnstwist surfaces registered typosquats imitating your brand for phishing." },
    ],
    tools: ["subfinder", "amass", "checkdmarc", "dnstwist"],
    how: [
      { t: "Enumerate", d: "Passive + active subdomain discovery (subfinder/amass/crt.sh) maps the full surface from a single apex domain." },
      { t: "Pivot to children", d: "Live discovered hosts become child assets — so a subdomain that's a real web app gets a real web scan, not re-enumeration." },
      { t: "Check email + takeover", d: "DMARC/SPF/DKIM and dangling-record checks run, each with the concrete record or cleanup to apply." },
    ],
    frameworks: "Domain findings map to SOC 2 (CC6.6/CC7.1), CIS 9.5 (email), and GDPR Art. 32 where a nexus exists.",
    faq: [
      { q: "What does a domain scan find?", a: "Every subdomain (incl. forgotten ones), dangling records vulnerable to takeover, your email-spoofing posture (DMARC/SPF/DKIM), and registered look-alike/typosquat domains." },
      { q: "Does it scan the subdomains it finds?", a: "Yes — a live discovered host becomes a child asset and gets the right scan (web, IP) instead of being re-enumerated, so coverage compounds." },
      { q: "Can it fix email spoofing?", a: "It checks DMARC/SPF/DKIM from public DNS and hands you the exact TXT record to publish — the highest-leverage anti-phishing fix." },
    ],
    seoTitle: "Domain & DNS Security — Subdomains, Takeover & DMARC | TensorShield",
    seoDesc: "Domain & DNS security: subdomain enumeration, subdomain-takeover detection, email-spoofing posture (DMARC/SPF/DKIM), and typosquat monitoring. Your attacker's-eye footprint.",
  },
};
