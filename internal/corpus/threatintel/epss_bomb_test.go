package threatintel

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

func gzipString(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ParseEPSSGzip must BOUND the decompressed stream so a gzip bomb (tiny .gz → gigabytes) can't OOM the
// in-process corpus refresher: over-cap data is truncated, not read in full.
func TestParseEPSSGzip_DecompressionCapBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("#model_version:v1,score_date:2026-05-29T00:00:00+0000\n")
	sb.WriteString("cve,epss,percentile\n")
	const rows = 5000
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&sb, "CVE-2024-%05d,0.50000,0.50000\n", i)
	}
	gz := gzipString(t, sb.String())

	// With the default (large) cap, every row parses.
	m, _, err := ParseEPSSGzip(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m) != rows {
		t.Fatalf("want %d rows under the default cap, got %d", rows, len(m))
	}

	// Lower the cap far below the decompressed size → the stream is truncated, so the parser reads only
	// a small prefix (a bomb stops at the ceiling instead of OOMing).
	orig := maxDecompressedEPSS
	defer func() { maxDecompressedEPSS = orig }()
	maxDecompressedEPSS = 1 << 10 // 1 KiB, vs a ~150 KiB decompressed CSV
	m2, _, err := ParseEPSSGzip(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("capped parse should not error (truncation is graceful): %v", err)
	}
	if len(m2) >= rows {
		t.Fatalf("decompression cap not enforced: parsed %d rows, want far fewer than %d", len(m2), rows)
	}
}
