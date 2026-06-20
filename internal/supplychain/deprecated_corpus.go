package supplychain

// DefaultDeprecatedCorpus is the checked-in snapshot of widely-used packages the
// maintainer has officially deprecated or abandoned, with the recommended
// replacement. Conservative (only well-known, unambiguous deprecations) so a
// match is high-confidence. The full per-package health signal (deps.dev /
// OpenSSF Scorecard) is a live-lookup follow-up.
func DefaultDeprecatedCorpus() []DeprecatedPackage {
	return []DeprecatedPackage{
		// npm — security-relevant (unmaintained networking / on the attack surface)
		{Ecosystem: "npm", Name: "request", Replacement: "got, axios, or node-fetch", SecurityRelevant: true,
			Note: "Fully deprecated in 2020; no longer maintained."},
		{Ecosystem: "npm", Name: "request-promise", Replacement: "got or axios", SecurityRelevant: true,
			Note: "Deprecated with request."},
		{Ecosystem: "npm", Name: "har-validator", Replacement: "a maintained schema validator", SecurityRelevant: true},
		// npm — hygiene (deprecated/renamed, low risk)
		{Ecosystem: "npm", Name: "node-uuid", Replacement: "uuid"},
		{Ecosystem: "npm", Name: "babel-core", Replacement: "@babel/core (Babel 7+)"},
		{Ecosystem: "npm", Name: "gulp-util", Replacement: "individual gulp modules"},
		{Ecosystem: "npm", Name: "tslint", Replacement: "eslint + typescript-eslint", Note: "Deprecated in favour of ESLint."},
		{Ecosystem: "npm", Name: "istanbul", Replacement: "nyc"},
		{Ecosystem: "npm", Name: "left-pad", Replacement: "String.prototype.padStart"},

		// pypi
		{Ecosystem: "pypi", Name: "nose", Replacement: "pytest or nose2", Note: "Unmaintained; broken on modern Python."},
		{Ecosystem: "pypi", Name: "distribute", Replacement: "setuptools", SecurityRelevant: false},
	}
}
