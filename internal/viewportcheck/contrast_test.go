package viewportcheck

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ADR 0022 §3 — the text tokens must meet WCAG AA against every ground they are drawn on.
//
// This computes the ratio from globals.css rather than asserting a hex string, so it survives a
// deliberate palette change and still fails a careless one. Asserting "--c-faint is #6A717E" would
// break on any redesign and prove nothing; asserting "whatever --c-faint is, it clears 4.5:1 on the
// darkest ground it sits on" is the property that actually matters.
//
// Two mistakes this would have caught, both made while implementing the ADR:
//   - a light value tuned against white (4.50) that scored 4.20 against the page background
//   - a dark value tuned against --c-surface (4.52) that scored 3.46 against --c-surface-3
// In both cases the ground I picked was not the hardest one on the page.

var tokenRe = regexp.MustCompile(`--c-([a-z0-9-]+):\s*(\d+)\s+(\d+)\s+(\d+)\s*;`)

type rgb struct{ r, g, b float64 }

func relLum(c rgb) float64 {
	f := func(v float64) float64 {
		v /= 255
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*f(c.r) + 0.7152*f(c.g) + 0.0722*f(c.b)
}

func contrast(a, b rgb) float64 {
	l1, l2 := relLum(a), relLum(b)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

// parseBlock pulls the token map out of one :root block (light = first, dark = the [data-theme] one).
func parseBlock(css string) map[string]rgb {
	out := map[string]rgb{}
	for _, m := range tokenRe.FindAllStringSubmatch(css, -1) {
		r, _ := strconv.ParseFloat(m[2], 64)
		g, _ := strconv.ParseFloat(m[3], 64)
		b, _ := strconv.ParseFloat(m[4], 64)
		out[m[1]] = rgb{r, g, b}
	}
	return out
}

func TestTextTokensMeetAAOnEveryGround(t *testing.T) {
	css := repoFile(t, "frontend/app/globals.css")

	// The dark palette lives in the `.dark` block; everything before it is light.
	//
	// This was originally written against `[data-theme="dark"]`, which this file does not use — so
	// the lookup returned -1, the test called t.Skip, and `go test` printed ok. Two mutation runs
	// (reverting each --c-faint to its known-failing value) both passed, which is how the dead guard
	// was found. A skip is not a pass, and a guard that cannot locate its subject must FAIL rather
	// than excuse itself, or it reports green for the rest of its life.
	darkAt := strings.Index(css, ".dark {")
	if darkAt < 0 {
		t.Fatal("could not find the `.dark {` palette block in globals.css.\n" +
			"The theme layout changed. Update this guard — do NOT skip: a contrast test that cannot " +
			"find the palette silently reports green forever.")
	}
	themes := map[string]map[string]rgb{
		"light": parseBlock(css[:darkAt]),
		"dark":  parseBlock(css[darkAt:]),
	}

	// Tokens used for TEXT, and every ground they can be drawn on. `faint` is included because it is
	// used 489 times, 321 of them on small text — whatever it was specified as, it is a text token.
	textTokens := []string{"ink", "muted", "faint"}
	grounds := []string{"bg", "surface", "surface-2", "surface-3"}

	const aaSmall = 4.5 // 12px caption text is "normal" text under WCAG, not large

	for theme, tok := range themes {
		for _, name := range textTokens {
			fg, ok := tok[name]
			if !ok {
				continue // a theme that does not redefine a token inherits the other block's value
			}
			for _, gname := range grounds {
				bg, ok := tok[gname]
				if !ok {
					continue
				}
				if got := contrast(fg, bg); got < aaSmall {
					t.Errorf("%s theme: --c-%s on --c-%s is %.2f:1, below the %.1f:1 AA floor for "+
						"small text.\nPick the value against the HARDEST ground on the page, not the "+
						"most convenient one — that is the mistake this guard exists to catch.",
						theme, name, gname, got, aaSmall)
				}
			}
		}
	}
}
