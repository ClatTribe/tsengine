package webagent

import (
	"strings"
	"testing"
)

// TestDiscoverSurface_FormActionAndFragment: the <form action> POST target is the injection sink;
// it must be surfaced + labelled even on a page flooded with same-page nav anchors, and same-page
// #fragments collapse to one endpoint (so nav links don't crowd the capped list). Regression for a
// real miss: a Tailwind template's contact form posted to send.php but the anchor links crowded it
// out of the endpoints list, so the agent never found the SQLi sink.
func TestDiscoverSurface_FormActionAndFragment(t *testing.T) {
	body := `<nav>
		<a href="index.html#features">f</a><a href="index.html#support">s</a>
		<a href="index.html#pricing">p</a><a href="index.html#about">a</a>
		<a href="signin.html">in</a><a href="signup.html">up</a></nav>
		<form action="send.php" method="POST"><input name="email"><input name="fullname"></form>`
	out := discoverSurface(body, "http://t/index.html")

	if !strings.Contains(out, "send.php") {
		t.Errorf("form action send.php not surfaced: %s", out)
	}
	if !strings.Contains(out, "POST submit target") {
		t.Errorf("form action not labelled as the sink: %s", out)
	}
	// same-page fragments collapsed (no #features noise; index.html appears once)
	if strings.Contains(out, "#features") || strings.Contains(out, "#support") {
		t.Errorf("same-page fragment not stripped: %s", out)
	}
}
