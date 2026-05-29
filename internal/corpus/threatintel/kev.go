package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// kevFeed is the subset of the CISA KEV JSON we consume.
type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CveID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"` // "2006-01-02"
	} `json:"vulnerabilities"`
}

// ParseKEV reads the CISA KEV JSON feed into a CVE→KEVStatus map. asOf is the
// catalog's dateReleased; version is catalogVersion (for the corpus version
// string). Every listed CVE is, by definition, Listed=true.
func ParseKEV(r io.Reader) (map[string]types.KEVStatus, time.Time, string, error) {
	var feed kevFeed
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil, time.Time{}, "", fmt.Errorf("threatintel: parse KEV: %w", err)
	}
	out := make(map[string]types.KEVStatus, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		st := types.KEVStatus{Listed: true}
		if v.DateAdded != "" {
			if d, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
				st.DateAdded = d.UTC()
			}
		}
		out[v.CveID] = st
	}
	asOf := parseKEVDate(feed.DateReleased)
	return out, asOf, feed.CatalogVersion, nil
}

// parseKEVDate tolerates the RFC3339-ish dateReleased ("2026-05-29T08:00:00.000Z")
// and falls back to now if unparseable.
func parseKEVDate(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
