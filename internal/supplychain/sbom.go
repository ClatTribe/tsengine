package supplychain

import (
	"encoding/json"
	"net/url"
	"strings"
)

// PackagesFromSBOM extracts the dependency set from a CycloneDX SBOM (as
// produced by syft `-o cyclonedx-json`, carried in tool.Result.Output). Each
// component's Package URL (purl) yields an (ecosystem, name, version). Returns
// nil for anything that isn't a CycloneDX SBOM — so it's safe to call over every
// tool result and let the non-SBOM ones no-op.
func PackagesFromSBOM(output any) []Package {
	s := toStr(output)
	// Cheap gate before the full unmarshal — every CycloneDX doc carries this.
	if s == "" || !strings.Contains(s, "CycloneDX") {
		return nil
	}
	var doc struct {
		Components []struct {
			Purl     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if json.Unmarshal([]byte(s), &doc) != nil {
		return nil
	}
	out := make([]Package, 0, len(doc.Components))
	for _, c := range doc.Components {
		if eco, name, ver, ok := parsePURL(c.Purl); ok {
			out = append(out, Package{Ecosystem: eco, Name: name, Version: ver, License: firstLicense(c.Licenses)})
		}
	}
	return out
}

// firstLicense pulls the first usable SPDX id / name / expression from a
// CycloneDX component's licenses[] (the field is irregular across producers).
func firstLicense(licenses []struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}) string {
	for _, l := range licenses {
		switch {
		case l.License.ID != "":
			return l.License.ID
		case l.Expression != "":
			return l.Expression
		case l.License.Name != "":
			return l.License.Name
		}
	}
	return ""
}

// parsePURL parses a Package URL — pkg:<type>/[<namespace>/]<name>@<version>
// [?qualifiers][#subpath] — into (ecosystem, name, version). The purl <type>
// is the ecosystem (npm, pypi, golang, …).
func parsePURL(purl string) (eco, name, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", "", false
	}
	body := purl[len("pkg:"):]
	// Strip qualifiers (?...) and subpath (#...).
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	slash := strings.IndexByte(body, '/')
	if slash <= 0 {
		return "", "", "", false
	}
	eco = strings.ToLower(body[:slash])
	rest := body[slash+1:] // [namespace/]name@version
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", "", "", false
	}
	namepart, version := rest[:at], rest[at+1:]
	// The name is the last path segment (namespace is dropped — the corpus keys
	// on the bare package name; scoped packages are not in the corpus today).
	if i := strings.LastIndexByte(namepart, '/'); i >= 0 {
		namepart = namepart[i+1:]
	}
	if dec, err := url.PathUnescape(namepart); err == nil {
		namepart = dec
	}
	if dec, err := url.PathUnescape(version); err == nil {
		version = dec
	}
	if eco == "" || namepart == "" {
		return "", "", "", false
	}
	return eco, namepart, version, true
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}
