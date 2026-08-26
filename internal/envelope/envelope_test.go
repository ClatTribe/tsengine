package envelope

import (
	"sync"
	"testing"
)

func TestEnvelope_IsAbsoluteUnderConcurrency(t *testing.T) {
	e := New(1000)
	var wg sync.WaitGroup
	var granted int64
	var mu sync.Mutex
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if e.Take() {
					mu.Lock()
					granted++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if got := int64(granted); got != 1000 || e.Left() != 0 {
		t.Fatalf("32 workers racing a 1000 grant: granted=%d left=%d", granted, e.Left())
	}
}

func TestTokenBudget_OverrunFlipsOnce(t *testing.T) {
	b := NewTokenBudget(100)
	if !b.Spend(60) || !b.Spend(40) {
		t.Fatal("spends within budget must be ok")
	}
	if b.Spend(1) {
		t.Error("the first spend past the budget must report false")
	}
	// The overrun IS recorded (101 consumed against 100 authorized) — honest accounting
	// of what actually happened, with Left() at zero and the breach already reported.
	if b.Spent() != 101 || b.Left() != 0 {
		t.Errorf("accounting: spent=%d left=%d", b.Spent(), b.Left())
	}
}
