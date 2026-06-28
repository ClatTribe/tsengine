package threatintel

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// ParseEPSS reads the FIRST.org EPSS CSV into a CVE→EPSSScore map. The first
// line is a comment carrying score_date (the snapshot as-of), e.g.:
//
//	#model_version:v2025.03.14,score_date:2026-05-29T00:00:00+0000
//	cve,epss,percentile
//	CVE-1999-0001,0.01030,0.74100
//
// r is the DECOMPRESSED CSV (use ParseEPSSGzip for the .csv.gz feed). Every
// row's AsOf is stamped with the file's score_date.
func ParseEPSS(r io.Reader) (map[string]types.EPSSScore, time.Time, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	asOf := time.Now().UTC()
	out := make(map[string]types.EPSSScore)
	headerSeen := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if t, ok := scoreDate(line); ok {
				asOf = t
			}
			continue
		}
		if !headerSeen {
			// First non-comment line is the column header (cve,epss,percentile).
			headerSeen = true
			continue
		}
		cve, score, pct, ok := parseEPSSRow(line)
		if !ok {
			continue
		}
		out[cve] = types.EPSSScore{Score: score, Percentile: pct, AsOf: asOf}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("threatintel: read EPSS: %w", err)
	}
	// Re-stamp AsOf now that score_date is known (comment precedes rows, so
	// this is normally already correct; defensive against ordering).
	return out, asOf, nil
}

// maxDecompressedEPSS bounds the GUNZIPPED EPSS stream so a decompression bomb (a tiny .csv.gz that
// expands to gigabytes) can't OOM the in-process corpus refresher (scheduler.CorpusRefresher runs this
// on a 24h clock inside the long-lived platform server). The real feed is ~10–15 MiB decompressed
// (~336k CVEs); 128 MiB is ~8× headroom for growth while capping a bomb at a survivable size. A var so
// tests can lower it. Over-cap data is truncated (EOF) — legit data is far under the cap, so it's never
// reached in practice; a bomb just stops at the ceiling instead of OOMing.
var maxDecompressedEPSS int64 = 128 << 20

// ParseEPSSGzip decompresses the .csv.gz feed and parses it (bounded against a gzip bomb).
func ParseEPSSGzip(r io.Reader) (map[string]types.EPSSScore, time.Time, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("threatintel: gunzip EPSS: %w", err)
	}
	defer func() { _ = gz.Close() }()
	return ParseEPSS(io.LimitReader(gz, maxDecompressedEPSS))
}

func parseEPSSRow(line string) (cve string, score, pct float64, ok bool) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return "", 0, 0, false
	}
	cve = strings.TrimSpace(parts[0])
	if !strings.HasPrefix(cve, "CVE-") {
		return "", 0, 0, false
	}
	s, err1 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	p, err2 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return cve, s, p, true
}

// scoreDate extracts score_date from the EPSS header comment.
func scoreDate(comment string) (time.Time, bool) {
	for _, field := range strings.Split(strings.TrimPrefix(comment, "#"), ",") {
		kv := strings.SplitN(strings.TrimSpace(field), ":", 2)
		if len(kv) == 2 && kv[0] == "score_date" {
			for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
				if t, err := time.Parse(layout, kv[1]); err == nil {
					return t.UTC(), true
				}
			}
		}
	}
	return time.Time{}, false
}
