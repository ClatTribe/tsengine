package platformapi

import (
	"strings"
	"testing"
	"time"
)

func TestGradeColor(t *testing.T) {
	cases := map[string]string{"A": "#2da44e", "B": "#2da44e", "C": "#bf8700", "D": "#cf222e", "F": "#cf222e", "?": "#9f9f9f"}
	for grade, want := range cases {
		if got := gradeColor(grade); got != want {
			t.Errorf("gradeColor(%q)=%s want %s", grade, got, want)
		}
	}
}

func TestBadgeSVG_RendersMessageAndColor(t *testing.T) {
	svg := badgeSVG("TensorShield", "Grade A", "#2da44e")
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatal("not a well-formed svg")
	}
	for _, want := range []string{"TensorShield", "Grade A", "#2da44e"} {
		if !strings.Contains(svg, want) {
			t.Errorf("svg should contain %q", want)
		}
	}
}

func TestBadgeSVG_EscapesInput(t *testing.T) {
	svg := badgeSVG("a<b>", `c&"d`, "#000")
	if strings.Contains(svg, "<b>") || strings.Contains(svg, `c&"`) {
		t.Error("svg must escape &, <, >, \" in label/message")
	}
	if !strings.Contains(svg, "&lt;b&gt;") || !strings.Contains(svg, "&amp;") {
		t.Error("expected escaped entities")
	}
}

func TestBadgeCache_TTL(t *testing.T) {
	c := &badgeCacheT{m: map[string]badgeEntry{}}
	now := time.Unix(1700000000, 0)
	c.put("acme.com", badgeEntry{grade: "A", score: 100, exp: now.Add(badgeTTL)})

	if e, ok := c.get("acme.com", now); !ok || e.grade != "A" {
		t.Fatalf("fresh entry should hit, got %+v ok=%v", e, ok)
	}
	if _, ok := c.get("acme.com", now.Add(badgeTTL+time.Second)); ok {
		t.Error("expired entry must miss")
	}
	if _, ok := c.get("unknown.com", now); ok {
		t.Error("absent entry must miss")
	}
}
