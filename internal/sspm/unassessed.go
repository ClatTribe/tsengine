package sspm

import (
	"reflect"
	"sort"
	"strings"
)

// unassessed.go says which parts of a SaaS snapshot carried nothing to look at.
//
// # The gap
//
// Every assessor here is deliberately silent about a setting the snapshot did not report — absent
// config is not insecure config (§10). That is right, and it is why a hardened org correctly yields
// zero findings. But it means a snapshot carrying almost nothing ALSO yields zero findings, and the
// response said only `findings_detected: 0`. POST {"login":"acme"} and the answer is
// indistinguishable from a tenant that was examined and came back clean.
//
// The device and identity ingests already say this out loud (deviceposture.Report.ChecksNotRun,
// identitythreat.Unevaluated). SaaS posture did not, and it is the ingest most likely to be posted
// by hand or by a half-scoped connector — GitHub's own live sync can only read what `read:org`
// covers, so per-member 2FA and installed apps are routinely absent by design.
//
// # Why reflection rather than a list per provider
//
// There are seven provider snapshots. A hand-written list of "the fields the checks read" would be
// seven lists to keep in step with seven assessors, and the first one to drift would quietly claim
// coverage that no longer exists. Reading the struct itself cannot drift: a field that exists is one
// an assessor can read, and a field left at its zero value is one the snapshot did not carry.
//
// The trade is that this reports at FIELD granularity, not check granularity — it says "the snapshot
// did not carry `apps`", not "the third-party-app check did not run". That is the honest direction
// to err: it describes exactly what was received rather than inferring which rules that starved.

// identityFields name a tenant rather than describing its posture. A snapshot carrying only these
// has told us WHO it is and nothing about how it is configured, so they never count as assessable —
// otherwise POST {"login":"acme"} would look like partial coverage.
var identityFields = map[string]bool{
	"login": true, "name": true, "id": true, "domain": true,
	"tenant": true, "tenant_id": true, "account": true, "account_id": true,
	"org": true, "org_id": true, "workspace": true, "workspace_id": true,
}

// UnassessedFields returns the snapshot fields that carried no data, and how many did carry data.
//
// A field is "carried" when it holds anything other than its zero value: a non-nil pointer, a
// non-empty slice or string, a true bool. Pointers are the important case — the snapshot types use
// *bool precisely so that "not reported" is distinguishable from "reported as off", and this reads
// that same distinction.
//
// Returns names in the JSON spelling the caller posted, so the message names what to add.
func UnassessedFields(snapshot any) (missing []string, carried int) {
	v := reflect.ValueOf(snapshot)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil, 0
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, 0
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		name := jsonName(f.Tag.Get("json"), f.Name)
		if name == "" || name == "-" || identityFields[name] {
			continue
		}
		if isCarried(v.Field(i)) {
			carried++
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return missing, carried
}

// UnassessedNote renders the honest one-liner for a snapshot, or "" when it carried enough to say
// something. The strong case — nothing assessable at all — is called out separately, because "we
// checked some of it" and "we checked none of it" are different claims and only one of them makes
// `findings_detected: 0` meaningless.
func UnassessedNote(provider string, snapshot any) string {
	missing, carried := UnassessedFields(snapshot)
	if len(missing) == 0 {
		return ""
	}
	if carried == 0 {
		return "This " + provider + " snapshot carried no settings at all, so nothing was assessed " +
			"— \"0 findings\" here is not a result. Missing: " + strings.Join(missing, ", ") + "."
	}
	return "These " + provider + " settings were not in the snapshot, so they were not assessed: " +
		strings.Join(missing, ", ") + ". Absent settings are never treated as findings, so their " +
		"silence is not a pass."
}

// jsonName extracts the wire name from a json tag, falling back to the Go field name.
func jsonName(tag, fallback string) string {
	if tag == "" {
		return strings.ToLower(fallback)
	}
	if i := strings.Index(tag, ","); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" {
		return strings.ToLower(fallback)
	}
	return tag
}

// isCarried reports whether a field holds data the snapshot actually supplied.
func isCarried(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		// A nil pointer is "not reported" — the whole reason these types use *bool.
		return !v.IsNil()
	case reflect.Slice, reflect.Map, reflect.String:
		return v.Len() > 0
	default:
		return !v.IsZero()
	}
}
