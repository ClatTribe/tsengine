package threatintel

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// vulnrichment.go ingests CISA's Vulnrichment (the ADP programme) — the SEVENTH free feed, and the
// only one carrying CISA's own DECISION assessment rather than a fact about the world or about us.
//
// WHY IT IS NOT REDUNDANT WITH THE SIX. KEV is binary and covers ~1,700 CVEs: exploited in the wild,
// or not listed. EPSS is a probability from a statistical model. ExploitDB and Metasploit answer
// whether a weapon exists. NVD gives severity. Nuclei says whether we can test for it. None of them
// answers the question SSVC's Automatable decision point does — CAN AN ATTACKER AUTOMATE THIS —
// which is the difference between a vulnerability someone exploits by hand against one target and
// one that can be driven across an estate. A defender ranking two CVEs with identical CVSS and
// neither on KEV has nothing to separate them today; Exploitation + Automatable + Technical Impact
// separates them, from the same authority that publishes KEV.
//
// The decision points are CISA's, recorded verbatim. We do not compute an SSVC decision from them
// (that requires the DEFENDER's own mission and deployment context, which we do not have and would
// have to invent) — we carry what CISA published and let it inform ranking.
// maxRecordBytes bounds one CVE record. The archive is ~300k small files; a single oversized one
// must not be read into memory whole.
const maxRecordBytes = 1 << 20

const VulnrichmentURL = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.tar.gz"

// ssvcRecord is the shape verified against the live repository, not assumed:
//
//	containers.adp[] where providerMetadata.shortName == "CISA-ADP",
//	  metrics[].other where type == "ssvc",
//	    content.options = [{"Exploitation":"none"},{"Automatable":"no"},{"Technical Impact":"total"}]
//
// The options are an ARRAY OF SINGLE-KEY OBJECTS rather than one object, which is why this decodes
// []map[string]string instead of a struct — a struct would silently produce zero values.
type ssvcRecord struct {
	Containers struct {
		ADP []struct {
			ProviderMetadata struct {
				ShortName string `json:"shortName"`
			} `json:"providerMetadata"`
			Metrics []struct {
				Other struct {
					Type    string `json:"type"`
					Content struct {
						ID      string              `json:"id"`
						Options []map[string]string `json:"options"`
					} `json:"content"`
				} `json:"other"`
			} `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

// ParseVulnrichment streams the repository tarball and returns CVE → SSVC decision points.
//
// Only CISA-ADP records count. The same file carries a "CVE" ADP container from the CNA, and
// crediting that as CISA's assessment would attribute someone else's judgement to the authority.
func ParseVulnrichment(r io.Reader) (map[string]*types.SSVC, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	out := map[string]*types.SSVC{}
	tr := tar.NewReader(io.LimitReader(gz, maxArchiveBytes))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		base := h.Name[strings.LastIndex(h.Name, "/")+1:]
		if !strings.HasPrefix(base, "CVE-") {
			continue
		}
		var rec ssvcRecord
		if json.NewDecoder(io.LimitReader(tr, maxRecordBytes)).Decode(&rec) != nil {
			continue // a record we cannot read is skipped, never guessed at
		}
		if s := ssvcFrom(rec); s != nil {
			out[strings.TrimSuffix(base, ".json")] = s
		}
	}
	return out, nil
}

func ssvcFrom(rec ssvcRecord) *types.SSVC {
	for _, adp := range rec.Containers.ADP {
		if adp.ProviderMetadata.ShortName != "CISA-ADP" {
			continue
		}
		for _, m := range adp.Metrics {
			if m.Other.Type != "ssvc" {
				continue
			}
			var s types.SSVC
			for _, opt := range m.Other.Content.Options {
				for k, v := range opt {
					switch k {
					case "Exploitation":
						s.Exploitation = v
					case "Automatable":
						s.Automatable = v
					case "Technical Impact":
						s.TechnicalImpact = v
					}
				}
			}
			// A record with no recognised decision point is not an assessment. Returning an empty
			// struct would put "CISA assessed this" against nothing.
			if s.Exploitation == "" && s.Automatable == "" && s.TechnicalImpact == "" {
				return nil
			}
			return &s
		}
	}
	return nil
}
