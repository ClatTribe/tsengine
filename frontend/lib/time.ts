// Timestamp helpers.
//
// WHY THIS EXISTS: a Go `time.Time` tagged `json:"...,omitempty"` is NOT omitted when it is the
// zero value — `omitempty` has no effect on a struct. So a field the API advertises as optional,
// and that the TypeScript type declares as `field?: string`, still arrives on every record as the
// string "0001-01-01T00:00:00Z". That string is TRUTHY. Every `!!incident.acknowledged_at` and
// `if (x.resolved_at)` in the codebase therefore reads "not set" as "set".
//
// This was not theoretical. It shipped two false claims on the incident queue at once: every open
// incident rendered as "acknowledged" (which also REPLACES the Acknowledge button, so the one
// action in the alert-response path could not be taken), on a page whose own scorecard said "0
// acknowledged"; and every incident claimed a CISA federal remediation deadline had passed.
//
// Producers are being fixed to send nil, but records already stored carry the zero time, so the
// reader must not trust the field's presence. Use `hasTime` instead of truthiness — always.

// Anything at or before this is a zero value wearing a date, not a real timestamp. Go's zero time
// is year 1; JavaScript's is 1970. Nothing this product records predates its own existence, so the
// bound is deliberately generous rather than clever.
const NOT_A_REAL_TIME = Date.UTC(2000, 0, 1);

/** True only when `v` is a timestamp that was actually set. Absent, unparseable, and zero-value
 *  timestamps are all false — the three ways "no time" reaches us. */
export function hasTime(v?: string | null): boolean {
  if (!v) return false;
  const t = new Date(v).getTime();
  return !Number.isNaN(t) && t > NOT_A_REAL_TIME;
}
