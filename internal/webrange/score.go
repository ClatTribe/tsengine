package webrange

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// ClassScore is the per-class breakdown.
type ClassScore struct {
	Real   int     `json:"real"`
	Found  int     `json:"found"`
	Recall float64 `json:"recall"`
	Youden float64 `json:"youden"` // recall - decoy_fp_rate for the class
	Decoys int     `json:"decoys"` // decoy targets of this class wrongly reported
}

// Score is the engagement result against the ground-truth manifest.
type Score struct {
	Seed         int64                 `json:"seed"`
	RealTotal    int                   `json:"real_total"`
	RealFound    int                   `json:"real_found"`
	Recall       float64               `json:"recall"`
	DecoyTotal   int                   `json:"decoy_total"`
	DecoyFlagged int                   `json:"decoy_flagged"` // decoys wrongly recorded (precision break)
	Invented     int                   `json:"invented"`      // findings matching no target at all
	ByClass      map[string]ClassScore `json:"by_class"`
	Missed       []string              `json:"missed,omitempty"`
	Pass         bool                  `json:"pass"`
}

// ScoreReport compares an agent report to the manifest. base is the served base
// URL (e.g. the httptest server URL) so manifest routes can be matched to the
// agent's recorded routes.
func ScoreReport(rep *webagent.Report, m Manifest, base string) Score {
	// index targets by their clean route key
	type tkey struct{ route, class string }
	realByRoute := map[string]Target{}  // route -> exploitable target
	decoyByRoute := map[string]Target{} // route -> decoy target
	for _, t := range m.Targets {
		route := base + t.Path + "?" + t.Param + "="
		if t.Exploitable {
			realByRoute[route] = t
		} else {
			decoyByRoute[route] = t
		}
	}

	found := map[tkey]bool{}
	s := Score{Seed: m.Seed, ByClass: map[string]ClassScore{}}
	for _, f := range rep.Findings {
		route := normalizeRoute(f.Route)
		if t, ok := realByRoute[route]; ok && sameClass(t.Class, f.Class) {
			found[tkey{route, t.Class}] = true
		} else if _, ok := decoyByRoute[route]; ok {
			s.DecoyFlagged++ // recorded a decoy → grounding failed
		} else {
			s.Invented++ // recorded something with no matching target
		}
	}

	cls := map[string]*ClassScore{}
	get := func(c string) *ClassScore {
		if cls[c] == nil {
			cls[c] = &ClassScore{}
		}
		return cls[c]
	}
	for route, t := range realByRoute {
		s.RealTotal++
		c := get(t.Class)
		c.Real++
		if found[tkey{route, t.Class}] {
			s.RealFound++
			c.Found++
		} else {
			s.Missed = append(s.Missed, t.ID+":"+t.Class+"@"+t.Path)
		}
	}
	s.DecoyTotal = len(decoyByRoute)
	// per-class decoy attribution
	decoyByClass := map[string]int{}
	for _, t := range m.Targets {
		if !t.Exploitable {
			decoyByClass[t.Class]++
		}
	}
	flaggedByClass := map[string]int{}
	for _, f := range rep.Findings {
		route := normalizeRoute(f.Route)
		if _, ok := decoyByRoute[route]; ok {
			flaggedByClass[f.Class]++
		}
	}

	for c, cs := range cls {
		if cs.Real > 0 {
			cs.Recall = float64(cs.Found) / float64(cs.Real)
		} else {
			cs.Recall = 1
		}
		cs.Decoys = flaggedByClass[c]
		fpRate := 0.0
		if d := decoyByClass[c]; d > 0 {
			fpRate = float64(cs.Decoys) / float64(d)
		}
		cs.Youden = cs.Recall - fpRate
		s.ByClass[c] = *cs
	}

	if s.RealTotal > 0 {
		s.Recall = float64(s.RealFound) / float64(s.RealTotal)
	} else {
		s.Recall = 1
	}
	sort.Strings(s.Missed)
	s.Pass = s.RealFound == s.RealTotal && s.DecoyFlagged == 0 && s.Invented == 0
	return s
}

// normalizeRoute strips a trailing payload value so a recorded route
// "base/p?x=PAYLOAD" or "base/p?x=" both key to "base/p?x=".
func normalizeRoute(route string) string {
	if i := strings.LastIndex(route, "="); i >= 0 {
		return route[:i+1]
	}
	return route
}

func sameClass(want, got string) bool {
	got = strings.ToLower(got)
	switch want {
	case ClassPathTrav:
		return got == "path_traversal" || got == "lfi" || got == "file_disclosure"
	case ClassCmdi:
		return got == "command_injection" || got == "cmdi" || got == "rce"
	case ClassRedirect:
		return got == "open_redirect" || got == "redirect"
	default:
		return got == want
	}
}

// Render formats a scorecard.
func Render(s Score) string {
	var b strings.Builder
	verdict := "PASS"
	if !s.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "seed=%d  recall=%.0f%% (%d/%d real)  decoys_flagged=%d/%d  invented=%d  verdict=%s\n",
		s.Seed, s.Recall*100, s.RealFound, s.RealTotal, s.DecoyFlagged, s.DecoyTotal, s.Invented, verdict)
	classes := make([]string, 0, len(s.ByClass))
	for c := range s.ByClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		cs := s.ByClass[c]
		fmt.Fprintf(&b, "  %-18s recall=%.0f%% (%d/%d)  decoys_flagged=%d  youden=%.2f\n",
			c, cs.Recall*100, cs.Found, cs.Real, cs.Decoys, cs.Youden)
	}
	if len(s.Missed) > 0 {
		fmt.Fprintf(&b, "  missed: %s\n", strings.Join(s.Missed, ", "))
	}
	return b.String()
}
