package apiauthz

import (
	"context"
	"testing"
)

type fakeLLM struct{ out string }

func (f fakeLLM) Generate(context.Context, string) (string, error) { return f.out, nil }

func TestProposeOperations_FiltersAndDedups(t *testing.T) {
	known := []Operation{{Method: "GET", URL: "https://api.x/orders/1", Class: ClassBOLA}}
	llm := fakeLLM{out: `Here are candidates:
	[
	  {"method":"get","url":"https://api.x/orders/2","class":"bola","marker":"victim@x"},
	  {"method":"DELETE","url":"https://api.x/admin/users/9","class":"bfla"},
	  {"method":"GET","url":"/orders/3","class":"bola"},
	  {"method":"GET","url":"https://api.x/orders/1","class":"bola"},
	  {"method":"GET","url":"https://api.x/x","class":"magic"}
	]`}
	ops, err := ProposeOperations(context.Background(), llm, known, 12)
	if err != nil {
		t.Fatal(err)
	}
	// orders/2 (ok) + admin/users/9 (ok bfla); /orders/3 dropped (not a full URL); orders/1 dropped (dup);
	// class "magic" dropped (unknown).
	if len(ops) != 2 {
		t.Fatalf("want 2 valid novel ops, got %d: %+v", len(ops), ops)
	}
	if ops[0].Method != "GET" || ops[0].Class != ClassBOLA {
		t.Errorf("first op should be the normalized BOLA GET, got %+v", ops[0])
	}
}

func TestProposeOperations_NilLLM(t *testing.T) {
	if _, err := ProposeOperations(context.Background(), nil, nil, 5); err == nil {
		t.Error("nil llm should error")
	}
}
