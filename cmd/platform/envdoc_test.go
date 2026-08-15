package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every setting the platform reads must be documented where we tell operators to look.
//
// The connect endpoint refuses an unconfigured connector with "…set X (see .env.example)". That is
// only useful if .env.example actually names X. It did not for the three CLOUD connectors:
// main.go read AWS_CFN_TEMPLATE_URL, AWS_TRUST_ACCOUNT_ID, GCP_TRUST_SERVICE_ACCOUNT and
// AZURE_TRUST_APP_ID, none of which appeared in the file — so an operator connecting AWS, the
// product's headline surface, was sent to a file that did not mention what they needed.
//
// Nothing checked, which is why it survived. This checks.
func TestEveryEnvVarReadIsDocumented(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(example)

	// Settings that are deliberately not operator-facing: runtime/platform plumbing a deploy does
	// not set by hand. Anything NOT listed here is expected to be documented.
	internal := map[string]bool{
		"PORT": true, "HOME": true, "PATH": true, "HOSTNAME": true,
	}

	got := regexp.MustCompile(`os\.Getenv\("([A-Z0-9_]+)"\)`).FindAllStringSubmatch(string(src), -1)
	if len(got) < 10 {
		t.Fatalf("only found %d env reads in main.go — the matcher is probably broken", len(got))
	}

	var missing []string
	seen := map[string]bool{}
	for _, m := range got {
		name := m[1]
		if seen[name] || internal[name] {
			continue
		}
		seen[name] = true
		// Documented = named anywhere in the file, whether as an assignment or in a comment
		// explaining a group of related settings.
		if !strings.Contains(doc, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("read by cmd/platform but absent from .env.example, so an operator told to "+
			"'see .env.example' cannot find them: %v", missing)
	}
}
