package types

// Severity is the canonical severity ladder. L1.5 hooks may demote within
// this ladder; demotions are logged to Scan.L15AuditLog so the security
// engineer audience can audit and override.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// allSeverities lists severities in descending order of seriousness.
func allSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

// Valid reports whether s is one of the canonical severities.
func (s Severity) Valid() bool {
	for _, x := range allSeverities() {
		if s == x {
			return true
		}
	}
	return false
}

// Rank returns a numeric rank where higher = more severe. Useful for
// sorting findings by severity. Unknown severities rank below SeverityInfo.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
