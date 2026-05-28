package nmap

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// xmlReport mirrors the relevant slice of nmap's XML output. We project
// open ports + service banners; the full report is preserved verbatim
// in raw_output for the security-engineer view.
type xmlReport struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []host   `xml:"host"`
}

type host struct {
	Addresses []address `xml:"address"`
	Status    status    `xml:"status"`
	Ports     ports     `xml:"ports"`
}

type address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type status struct {
	State string `xml:"state,attr"`
}

type ports struct {
	Ports []port `xml:"port"`
}

type port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    state   `xml:"state"`
	Service  service `xml:"service"`
}

type state struct {
	State string `xml:"state,attr"`
}

type service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

// highRiskServices are unencrypted or commonly-misconfigured services
// that warrant elevated severity when found open. The L1.5 hooks (Phase
// 4) will refine these; for now we surface them at medium so the
// security engineer notices.
var highRiskServices = map[string]struct{}{
	"telnet":  {},
	"ftp":     {},
	"rlogin":  {},
	"rsh":     {},
	"tftp":    {},
	"vnc":     {},
	"redis":   {},
	"memcached": {},
	"mongodb": {},
	"elasticsearch": {},
}

// parseXML turns nmap's XML output into one finding per open port.
func parseXML(blob []byte) []types.SandboxEmittedFinding {
	if len(blob) == 0 {
		return nil
	}
	var rep xmlReport
	if err := xml.Unmarshal(blob, &rep); err != nil {
		return nil
	}

	var out []types.SandboxEmittedFinding
	for _, h := range rep.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		hostAddr := primaryAddr(h.Addresses)
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			out = append(out, portToFinding(hostAddr, p))
		}
	}
	return out
}

func primaryAddr(addrs []address) string {
	for _, a := range addrs {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Addr
	}
	return ""
}

func portToFinding(host string, p port) types.SandboxEmittedFinding {
	endpoint := fmt.Sprintf("%s:%s/%s", host, p.PortID, p.Protocol)
	svc := strings.ToLower(strings.TrimSpace(p.Service.Name))
	sev := types.SeverityInfo
	if _, risky := highRiskServices[svc]; risky {
		sev = types.SeverityMedium
	}
	title := fmt.Sprintf("Open port %s/%s (%s)", p.PortID, p.Protocol, p.Service.Name)
	if p.Service.Product != "" {
		title = fmt.Sprintf("%s on %s/%s — %s %s", p.Service.Name, p.PortID, p.Protocol, p.Service.Product, p.Service.Version)
	}
	// We preserve the structured port info as raw_output in JSON form
	// — Finding.RawOutput is json.RawMessage, and downstream readers
	// (webappsec) expect JSON. The original XML survives in
	// ToolResult.Output for security engineers who want the verbatim
	// nmap form.
	raw, _ := json.Marshal(p)
	return types.SandboxEmittedFinding{
		RuleID:          "nmap::open-port::" + svc,
		Tool:            "nmap",
		Severity:        sev,
		Endpoint:        endpoint,
		Title:           strings.TrimSpace(title),
		RawOutput:       raw,
		MITRETechniques: []string{"T1046"}, // network service discovery
		ToolArgs: map[string]string{
			"port":     p.PortID,
			"protocol": p.Protocol,
			"service":  p.Service.Name,
			"product":  p.Service.Product,
			"version":  p.Service.Version,
		},
	}
}
