// Package toolsbundle blank-imports every OSS tool wrapper so their init() self-registers the tool in
// the global tool registry. Any binary that resolves asset handlers on the HOST (cmd/tsengine for the CLI,
// cmd/platform for the multi-tenant server) MUST import this — a handler's PlanAnchors does
// common.ResolveTools(names) against the registry, so an unpopulated registry plans ZERO anchors and every
// scan silently produces zero findings.
//
// This package is the single source of tool registration so the binaries can't drift: cmd/platform once
// imported NO tool wrappers, so platform-driven scans returned 0 findings for every asset while the CLI
// (which imported them inline) worked — a real, silent break of the core "scan an asset → see findings"
// flow. Centralizing the imports here makes that class of drift impossible. The tools EXECUTE in the
// sandbox (cmd/tool-server), but the host needs the registry populated to plan + describe dispatches.
package toolsbundle

import (
	_ "github.com/ClatTribe/tsengine/internal/tool/amass"
	_ "github.com/ClatTribe/tsengine/internal/tool/apkid"
	_ "github.com/ClatTribe/tsengine/internal/tool/bandit"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkdmarc"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkov"
	_ "github.com/ClatTribe/tsengine/internal/tool/cloudfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/codeql"
	_ "github.com/ClatTribe/tsengine/internal/tool/cosign"
	_ "github.com/ClatTribe/tsengine/internal/tool/crtsh"
	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/dnstwist"
	_ "github.com/ClatTribe/tsengine/internal/tool/dockle"
	_ "github.com/ClatTribe/tsengine/internal/tool/ffuf"
	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/gosec"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/hadolint"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/hydra"
	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/katana"
	_ "github.com/ClatTribe/tsengine/internal/tool/kics"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
	_ "github.com/ClatTribe/tsengine/internal/tool/naabu"
	_ "github.com/ClatTribe/tsengine/internal/tool/nikto"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/openapi"
	_ "github.com/ClatTribe/tsengine/internal/tool/osvscanner"
	_ "github.com/ClatTribe/tsengine/internal/tool/padbuster"
	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
	_ "github.com/ClatTribe/tsengine/internal/tool/schemathesis"
	_ "github.com/ClatTribe/tsengine/internal/tool/scoutsuite"
	_ "github.com/ClatTribe/tsengine/internal/tool/seedauth"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
	_ "github.com/ClatTribe/tsengine/internal/tool/syft"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
)
