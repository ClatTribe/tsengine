package detectionskill

import (
	"context"
	"log/slog"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// triage.go adapts a skill Library to detect.SkillTriager, so an opening incident carries the
// detection engineer's reasoning (ADR 0017). The dependency runs one way — detect knows nothing
// about skills; it declares a local interface and this package satisfies it.
//
// Everything here is BEST-EFFORT by contract. Triage sits on the incident-opening path, which must
// never be blocked or failed by a third-party skill or a flaky model: no match, a model error, or a
// refused verdict all degrade to "no annotation", leaving the alert exactly as it is today.
//
// Note what this adapter cannot do: it returns annotation only. It cannot stop an incident from
// opening, because detect.SkillTriager has no channel for that. A "benign" verdict from an injected
// skill therefore cannot mute a real alert — the property is structural, not a rule someone has to
// remember.

// Triager runs a skill library over opening incidents.
type Triager struct {
	Library Library
	LLM     LLM
	// Log receives best-effort diagnostics (a refused verdict is worth knowing about — it may be a
	// hostile skill). Optional; nil uses the default logger.
	Log *slog.Logger
}

// NewTriager builds a detect.SkillTriager from a library and a model. Returns nil when either is
// missing, so the caller can assign it straight onto Detector.Triager and get today's behaviour when
// skills are not configured.
func NewTriager(lib Library, llm LLM) detect.SkillTriager {
	if len(lib) == 0 || llm == nil {
		return nil
	}
	return &Triager{Library: lib, LLM: llm}
}

// Triage implements detect.SkillTriager.
func (t *Triager) Triage(ctx context.Context, f types.Finding, siblings []types.Finding) (detect.SkillVerdict, bool) {
	matches := t.Library.For(f)
	if len(matches) == 0 {
		return detect.SkillVerdict{}, false // honest: no skill covers this rule
	}
	// First match wins for the annotation. Library order is deterministic, so the same alert always
	// gets the same skill — an annotation that changed between runs would be worse than none.
	m := matches[0]

	res, err := Run(ctx, t.LLM, m.Skill, PhaseTriage, f, siblings)
	if err != nil {
		// A refused verdict is a signal, not just noise: it may be an ungrounded claim from a hostile
		// skill. Log it and leave the alert unannotated.
		t.logger().Warn("[skills] triage produced no usable verdict",
			"skill", m.Skill.Name, "digest", shortDigest(m.Skill.Digest), "rule", f.RuleID, "err", err)
		return detect.SkillVerdict{}, false
	}
	return detect.SkillVerdict{
		Verdict:   string(res.Verdict),
		Rationale: res.Rationale,
		Skill:     m.Skill.Name + "@" + shortDigest(m.Skill.Digest),
	}, true
}

func (t *Triager) logger() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.Default()
}
