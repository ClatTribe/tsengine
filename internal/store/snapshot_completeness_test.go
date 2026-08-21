package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// The seven-place wiring for a new store entity has a hole that nothing fails on, and
// this closes it as a CLASS rather than one more per-entity test.
//
// EvalRuns had a Store method, a Memory map, a File.PutEvalRun that called persist(), a
// SQLite table and a Postgres table — every place except the file store's Snapshot
// struct. Nothing failed: Put returned nil, the file was written, and the runs were gone
// after a restart. Anyone adding the next entity by following the same pattern inherits
// the same hole, so the fix has to read the code rather than remember a name.
//
// Three failure modes, all silent, all checked here:
//
//  1. the Memory map has no Snapshot field         → written nowhere
//  2. the field exists but snapshot() never sets it → written empty
//  3. the field is set but load() never reads it    → written, then ignored on restart
//
// (1) is structural and checked by reflection. (2) and (3) are checked against the
// source of the two functions, which is cruder than a behavioural round-trip and buys
// the thing a round-trip would need: no fixture per entity, so the guard does not rot
// the moment someone adds a type that is awkward to construct.
func TestSnapshotCoversEveryMemoryCollection(t *testing.T) {
	// Deliberate omissions, each needing the reason it is not durable state.
	notPersisted := map[string]string{}

	var memMaps []string
	mt := reflect.TypeOf(Memory{})
	for i := 0; i < mt.NumField(); i++ {
		if f := mt.Field(i); f.Type.Kind() == reflect.Map {
			memMaps = append(memMaps, f.Name)
		}
	}
	snapByName := map[string]string{} // lowercased → declared name
	st := reflect.TypeOf(Snapshot{})
	for i := 0; i < st.NumField(); i++ {
		n := st.Field(i).Name
		snapByName[strings.ToLower(n)] = n
	}

	var missing []string
	for _, name := range memMaps {
		if _, ok := notPersisted[strings.ToLower(name)]; ok {
			continue
		}
		if _, ok := snapByName[strings.ToLower(name)]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("Memory holds %d collection(s) with no Snapshot field, so the file store writes "+
			"them nowhere and loses them on restart — silently, because Put still returns nil: %v\n"+
			"Add the field to Snapshot (and to Export()/load()), or list it in notPersisted with "+
			"the reason it is not durable.", len(missing), missing)
	}

	writes, reads := snapshotFieldUse(t)
	for _, declared := range snapByName {
		if !writes[declared] {
			t.Errorf("Snapshot.%s is declared but Export() never assigns it — the file store "+
				"writes it empty on every save", declared)
		}
		if !reads[declared] {
			t.Errorf("Snapshot.%s is declared but load() never reads it — whatever was saved is "+
				"discarded on restart", declared)
		}
	}
}

// snapshotFieldUse reports which Snapshot fields the snapshot() method assigns and which
// load() reads, by parsing memory.go.
func snapshotFieldUse(t *testing.T) (writes, reads map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "memory.go", nil, 0)
	if err != nil {
		t.Fatalf("parse memory.go: %v", err)
	}
	writes, reads = map[string]bool{}, map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		switch fn.Name.Name {
		case "Export":
			// Keys of the returned Snapshot composite literal.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				if id, ok := kv.Key.(*ast.Ident); ok {
					writes[id.Name] = true
				}
				return true
			})
		case "load":
			// Any selector on the parameter, e.g. s.ComplianceSnaps.
			param := "s"
			if len(fn.Type.Params.List) > 0 && len(fn.Type.Params.List[0].Names) > 0 {
				param = fn.Type.Params.List[0].Names[0].Name
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == param {
					reads[sel.Sel.Name] = true
				}
				return true
			})
		}
	}
	if len(writes) == 0 || len(reads) == 0 {
		t.Fatal("could not find Export()/load() in memory.go — this guard is not running")
	}
	return writes, reads
}
