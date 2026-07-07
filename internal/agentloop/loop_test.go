package agentloop

import (
	"strings"
	"testing"
)

func TestParseAction(t *testing.T) {
	cases := []struct {
		name, in, wantTool string
		wantErr            bool
	}{
		{"plain", `{"thought":"t","tool":"read_source","args":{"path":"a.go"}}`, "read_source", false},
		{"fenced", "```json\n{\"tool\":\"finish\",\"args\":{}}\n```", "finish", false},
		{"prose-prefix", `Sure! {"tool":"grep_code","args":{"pattern":"x"}} done`, "grep_code", false},
		{"wrapped-action", `{"thought":"t","action":{"tool":"record_issue","args":{}}}`, "record_issue", false},
		{"no-tool", `{"thought":"t"}`, "", true},
		{"not-json", `not a json action at all`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := ParseAction(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && a.Tool != c.wantTool {
				t.Errorf("tool=%q want %q", a.Tool, c.wantTool)
			}
		})
	}
	// the wrapped form must carry the OUTER thought through.
	a, _ := ParseAction(`{"thought":"outer","action":{"tool":"x","args":{}}}`)
	if a.Thought != "outer" {
		t.Errorf("wrapped thought = %q, want outer", a.Thought)
	}
}

func TestAppendCapped(t *testing.T) {
	var tr []string
	for i := 0; i < 40; i++ {
		tr = AppendCapped(tr, "entry")
	}
	if len(tr) != 24 {
		t.Errorf("transcript should cap at 24, got %d", len(tr))
	}
	// an over-long entry is truncated.
	tr = AppendCapped(nil, strings.Repeat("x", 5000))
	if len(tr[0]) > 1850 {
		t.Errorf("over-long entry should be truncated, got %d", len(tr[0]))
	}
}

func TestCompactArgs(t *testing.T) {
	got := CompactArgs(map[string]any{"k": strings.Repeat("v", 500)})
	if len(got) > 205 || !strings.HasSuffix(got, "...") {
		t.Errorf("compact args should truncate to ~200 with ellipsis, got len %d", len(got))
	}
}
