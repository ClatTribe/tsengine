package detectionskill

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// certify.go turns a validated skill verdict into compliance evidence.
//
// This is the half of the Detection Skills adoption that is ours alone (ADR 0017). Every other
// consumer of the format stops at a verdict — malicious/benign, the analyst moves on. We can carry it
// further: a verdict about a real finding, whose CWE already maps to controls across 22 frameworks,
// is an ASSESSMENT of those controls. Recorded with provenance and signed by a named human, it is
// exactly what an auditor asks for.
//
//	Skills are the input. Evidence is the output.
//
// THE GROUNDING RULE, and the reason this is safe: a certification INHERITS its control set from the
// findings the verdict cited. It never invents one. A third-party skill therefore cannot claim "this
// affects SOC 2 CC6.1" — the controls come from the CWE crosswalk on findings the engine actually
// emitted (the compliance.map L1.5 hook). There is no field on Skill or Proposal through which a
// control could be supplied, so this is structural, not a check that could be forgotten.
//
// A benign verdict certifies too. "We assessed this control and found no violation" is evidence an
// auditor wants; discarding it would throw away half the value of running the skill.

// Certification is a skill verdict rendered as compliance evidence.
//
// It is a PROPOSAL until a named human attests it — the §18.4 rule that the engine proposes and never
// itself decides, attests, or signs.
type Certification struct {
	// What was concluded, and on what.
	Verdict   Verdict  `json:"verdict"`
	Rationale string   `json:"rationale,omitempty"`
	Evidence  []string `json:"evidence"` // finding ids the verdict rests on

	// Which controls this assessment speaks to — INHERITED from the cited findings, never invented.
	Controls *types.Compliance `json:"controls,omitempty"`

	// Provenance: exactly which skill version produced it (ADR 0017 pins this).
	SkillName   string `json:"skill_name"`
	SkillDigest string `json:"skill_digest"`

	AssessedAt time.Time `json:"assessed_at"`

	// Human accountability. Empty until a named person attests.
	AttestedBy string    `json:"attested_by,omitempty"`
	AttestedAt time.Time `json:"attested_at,omitzero"`
}

// Certify renders a validated Result as evidence, inheriting controls from the cited findings.
//
// `findings` is the incident's finding set; only those cited by the Result contribute controls.
func Certify(r Result, findings []types.Finding, now time.Time) (Certification, error) {
	if r.Verdict == "" {
		return Certification{}, fmt.Errorf("cannot certify an empty verdict — validate the proposal first")
	}
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}

	var cited []types.Finding
	for _, id := range r.Evidence {
		f, ok := byID[id]
		if !ok {
			// Result.Validate already refused unknown ids; reaching here means a caller assembled a
			// Result by hand. Refuse rather than silently certify against nothing.
			return Certification{}, fmt.Errorf("cannot certify: evidence %q is not among the findings supplied", id)
		}
		cited = append(cited, f)
	}

	return Certification{
		Verdict:     r.Verdict,
		Rationale:   r.Rationale,
		Evidence:    append([]string(nil), r.Evidence...),
		Controls:    unionCompliance(cited),
		SkillName:   r.SkillName,
		SkillDigest: r.SkillDigest,
		AssessedAt:  now.UTC(),
	}, nil
}

// Attest records the named human who stands behind this assessment. The engine can reach a verdict;
// only a person can accept it as evidence (§18.4). An unnamed attestation is refused — "approved by
// nobody" is not accountability, and an auditor cannot follow it up.
func (c Certification) Attest(by string, now time.Time) (Certification, error) {
	by = strings.TrimSpace(by)
	if by == "" {
		return c, fmt.Errorf("attestation needs a named human — evidence without an accountable person is not evidence")
	}
	c.AttestedBy = by
	c.AttestedAt = now.UTC()
	return c, nil
}

// Attested reports whether a named human has signed off.
func (c Certification) Attested() bool { return c.AttestedBy != "" }

// ControlCount is the number of distinct controls this assessment speaks to, across all frameworks.
func (c Certification) ControlCount() int {
	if c.Controls == nil {
		return 0
	}
	n := 0
	forEachControlList(c.Controls, func(_ string, ids []string) { n += len(ids) })
	return n
}

// Frameworks lists the frameworks this assessment touches, in stable order.
func (c Certification) Frameworks() []string {
	if c.Controls == nil {
		return nil
	}
	var out []string
	forEachControlList(c.Controls, func(field string, ids []string) {
		if len(ids) > 0 {
			out = append(out, field)
		}
	})
	sort.Strings(out)
	return out
}

// Summary is the one-line an auditor reads in a report.
func (c Certification) Summary() string {
	who := "proposed (unattested)"
	if c.Attested() {
		who = "attested by " + c.AttestedBy
	}
	if n := c.ControlCount(); n > 0 {
		return fmt.Sprintf("%s — %d control(s) across %s, via skill %s@%s, %s",
			c.Verdict, n, strings.Join(c.Frameworks(), ", "), c.SkillName, shortDigest(c.SkillDigest), who)
	}
	// Honest when the cited findings carry no mapping: an assessment with no control nexus is still a
	// recorded assessment, it just is not compliance evidence. Never dressed up as one.
	return fmt.Sprintf("%s — no control mapping on the cited findings, via skill %s@%s, %s",
		c.Verdict, c.SkillName, shortDigest(c.SkillDigest), who)
}

// unionCompliance merges the control sets of the cited findings, deduped and sorted.
//
// Implemented by reflection over types.Compliance rather than 22 hand-written cases: §8 already
// requires a new framework to be added in four places, and a hand-rolled union here would silently
// become a fifth that drifts. Reflection means a framework added to the struct is included the day it
// exists. TestUnionCoversEveryFramework asserts this.
func unionCompliance(findings []types.Finding) *types.Compliance {
	sets := map[string]map[string]bool{}
	any := false

	for _, f := range findings {
		if f.Compliance == nil {
			continue
		}
		forEachControlList(f.Compliance, func(field string, ids []string) {
			for _, id := range ids {
				if id = strings.TrimSpace(id); id != "" {
					if sets[field] == nil {
						sets[field] = map[string]bool{}
					}
					sets[field][id] = true
					any = true
				}
			}
		})
	}
	if !any {
		return nil
	}

	out := &types.Compliance{}
	v := reflect.ValueOf(out).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Type.Kind() != reflect.Slice {
			continue
		}
		got := sets[t.Field(i).Name]
		if len(got) == 0 {
			continue
		}
		ids := make([]string, 0, len(got))
		for id := range got {
			ids = append(ids, id)
		}
		sort.Strings(ids) // deterministic: the same evidence must render identically every run (§10)
		v.Field(i).Set(reflect.ValueOf(ids))
	}
	return out
}

// forEachControlList visits every []string framework field on a Compliance value.
func forEachControlList(c *types.Compliance, fn func(field string, ids []string)) {
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Slice || t.Field(i).Type.Elem().Kind() != reflect.String {
			continue
		}
		fn(t.Field(i).Name, f.Interface().([]string))
	}
}
