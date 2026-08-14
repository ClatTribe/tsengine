package toolsbundle

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot walks up from this package to the module root, so the image-coverage tests can read the
// sandbox Dockerfile regardless of where `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found walking up from the test dir")
	return ""
}
