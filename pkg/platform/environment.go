package platform

import "strings"

// EnvironmentMetaKey is where an asset's declared environment lives on Asset.Meta. One constant so
// the pentest gate (internal/platformapi) and the ranking (internal/crossdetect) read the same field.
const EnvironmentMetaKey = "environment"

// DeclaredEnvironment returns "production", "staging" or "development" when a human has set one, and
// "" otherwise. It deliberately does not default: the pentest gate treats "" as production (the safe
// reading for an attack), while ranking treats "" as UNKNOWN and moves nothing — each consumer owns
// what silence means for it, and neither may read it as a fact.
func (a Asset) DeclaredEnvironment() string {
	switch v := strings.TrimSpace(a.Meta[EnvironmentMetaKey]); v {
	case "production", "staging", "development":
		return v
	}
	return ""
}
