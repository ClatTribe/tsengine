package tool

import "testing"

// TestURLTarget: dispatch_oss agents pass {"url":...} (matching the help's sqlmap example), so the
// URL-based OSS wrappers must accept "url" as an alias for "target" — else the dispatch silently
// died with "missing required arg 'target'". Regression for that whole class (wpscan/nuclei/ffuf/
// padbuster), mirroring sqlmap's own url-alias.
func TestURLTarget(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"target only", Args{"target": "http://t/"}, "http://t/"},
		{"url alias", Args{"url": "http://u/"}, "http://u/"},
		{"target wins over url", Args{"target": "http://t/", "url": "http://u/"}, "http://t/"},
		{"whitespace target falls through to url", Args{"target": "   ", "url": "http://u/"}, "http://u/"},
		{"neither", Args{}, ""},
		{"non-string url ignored", Args{"url": 42}, ""},
	}
	for _, c := range cases {
		if got := URLTarget(c.args); got != c.want {
			t.Errorf("%s: URLTarget(%v) = %q, want %q", c.name, c.args, got, c.want)
		}
	}
}
