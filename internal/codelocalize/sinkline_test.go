package codelocalize

import (
	"context"
	"testing"
)

func TestSinkLines_PointToTheStrongSinkLine(t *testing.T) {
	// the db.Query strong sink is on line 3 (1-based).
	f := File{Path: "store/users.go", Content: "package store\n" + // 1
		"func Find(db *sql.DB, name string) {\n" + // 2
		"\tdb.Query(\"SELECT * FROM u WHERE n='\" + name + \"'\")\n" + // 3
		"}\n"} // 4
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, Repo{f})
	if len(res.Ranked) == 0 {
		t.Fatal("no candidate")
	}
	got := res.Ranked[0].SinkLines
	if len(got) != 1 || got[0] != 3 {
		t.Fatalf("SinkLines should point to line 3, got %v", got)
	}
}

func TestSinkLines_EmptyForWeakOnly(t *testing.T) {
	// a file with only a weak `select ` token (no strong sink) carries no sink lines.
	f := File{Path: "a.go", Content: "// select from the menu\nvar x = 1\n"}
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, Repo{f})
	for _, c := range res.Ranked {
		if len(c.SinkLines) != 0 {
			t.Fatalf("weak-only candidate should have no SinkLines, got %v", c.SinkLines)
		}
	}
}
