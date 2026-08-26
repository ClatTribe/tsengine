package grc

import (
	"strings"
	"testing"
)

// The corpus is data, and data drifts. These guard the properties the answer logic RELIES on —
// each one, if violated, produces a question that silently cannot be answered correctly rather
// than a compile error.

func TestCorpusIDsAreUnique(t *testing.T) {
	// A duplicate id would make the attest endpoint answer whichever copy it found first and
	// leave the other permanently unanswered, with nothing to show for it.
	seen := map[string]bool{}
	for _, q := range standardQuestionnaire() {
		if seen[q.ID] {
			t.Errorf("duplicate question id %q", q.ID)
		}
		seen[q.ID] = true
	}
}

func TestObservedQuestionsDeclareTheirEvidence(t *testing.T) {
	for _, q := range observedQuestions {
		if q.Evidence != QObserved {
			t.Errorf("%s is in the observed list but marked %q", q.ID, q.Evidence)
		}
		if len(q.Sources) == 0 {
			// Without a source the answer logic cannot tell "assessed and clean" from "never
			// looked", and would fall through to Yes — the exact regression this whole file's
			// sibling exists to prevent.
			t.Errorf("%s is observed but names no evidence source, so it would answer Yes for a "+
				"tenant with nothing connected", q.ID)
		}
		if len(q.Controls) == 0 {
			t.Errorf("%s is observed but maps to no control, so no finding could ever flip it to "+
				"In Progress", q.ID)
		}
		if q.Why != "" {
			t.Errorf("%s is observed but carries a Why, which is the attested tier's field", q.ID)
		}
	}
}

func TestEverySourceIsOneWeCanActuallyDetect(t *testing.T) {
	// A source nothing can set means the question reads "connect X to answer this" forever,
	// telling the reader to connect something that is not a connectable thing. That happened
	// once already with a "data" source for the warehouse question.
	for _, q := range observedQuestions {
		for _, s := range q.Sources {
			if !knownSources[s] {
				t.Errorf("%s names source %q, which assessedSources can never produce — the question "+
					"would sit at Not assessed forever, naming a source that does not exist", q.ID, s)
			}
		}
	}
}

// The mirror: the vocabulary must not grow entries nothing uses, or the guard above stops
// meaning anything — it would pass for any source at all.
func TestKnownSourcesAreAllUsed(t *testing.T) {
	used := map[string]bool{}
	for _, q := range observedQuestions {
		for _, s := range q.Sources {
			used[s] = true
		}
	}
	for s := range knownSources {
		if !used[s] {
			t.Errorf("source %q is in the vocabulary but no question uses it — either a question is "+
				"missing or the entry is dead weight that weakens the check above", s)
		}
	}
}

func TestAttestedQuestionsDeclareWhyWeCannotAnswer(t *testing.T) {
	for _, q := range attestedQuestions {
		if q.Evidence != QAttested {
			t.Errorf("%s is in the attested list but marked %q", q.ID, q.Evidence)
		}
		if len(q.Sources) != 0 {
			// A source on an attested question is a contradiction: if something could evidence
			// it, it should be observed. Left in, the reader is told to connect a system that
			// would not change the answer.
			t.Errorf("%s is attested but names sources %v — if a source can answer it, it belongs "+
				"in the observed set", q.ID, q.Sources)
		}
		if strings.TrimSpace(q.Why) == "" {
			t.Errorf("%s asks for a human answer without saying why we cannot answer it ourselves — "+
				"the reader cannot tell 'nobody looked' from 'nothing can look'", q.ID)
		}
	}
}

func TestCorpusIsSubstantialAndBalanced(t *testing.T) {
	all := standardQuestionnaire()
	// Floors, not exact counts — the corpus should grow. They exist because a corpus that
	// SHRANK would still pass every other test here while quietly answering a narrower
	// document than the one a buyer sent (CLAUDE.md §14.2: a corpus must not shrink).
	if len(all) < 45 {
		t.Errorf("corpus has %d questions; a SIG-Lite-shaped set should not fall below 45", len(all))
	}
	if len(observedQuestions) < 30 {
		t.Errorf("only %d observed questions — the evidenced half is what distinguishes this from a "+
			"form someone fills in by hand", len(observedQuestions))
	}
	if len(attestedQuestions) < 10 {
		t.Errorf("only %d attested questions — dropping them would answer an easier document than the "+
			"one a buyer actually sends", len(attestedQuestions))
	}
	// Domains are what a procurement reader scans by; a corpus collapsed into two domains is
	// harder to read than a shorter one spread properly.
	domains := map[string]bool{}
	for _, q := range all {
		domains[q.Domain] = true
	}
	if len(domains) < 10 {
		t.Errorf("only %d domains across %d questions", len(domains), len(all))
	}
}

func TestQuestionByID(t *testing.T) {
	if q := QuestionByID("AC-1"); q == nil || q.Evidence != QObserved {
		t.Errorf("AC-1 lookup = %v", q)
	}
	if q := QuestionByID("HR-1"); q == nil || q.Evidence != QAttested {
		t.Errorf("HR-1 lookup = %v", q)
	}
	if q := QuestionByID("nope"); q != nil {
		// The attest endpoint 404s on nil. Returning a zero-value question instead would let
		// someone record an answer to a question that does not exist.
		t.Errorf("unknown id returned %v, want nil", q)
	}
}
