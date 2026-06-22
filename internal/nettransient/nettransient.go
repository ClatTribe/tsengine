// Package nettransient classifies an HTTP/transport error as a transient blip worth retrying
// (timeout / connection reset / dropped connection) vs a permanent fault (connection refused =
// service down, no such host = DNS, bad URL). It is shared by every live active-test prober —
// the pentest active-exploit prober and the apiauthz BOLA/BFLA differential prober — so a single
// network blip never silently produces a false result (an unproven exploit or a missed authz
// bypass) inconsistently across the active-testing surface.
package nettransient

import (
	"errors"
	"net"
	"strings"
)

// transientSignals are substrings of a transport error that mean "retry might help".
var transientSignals = []string{
	"connection reset", "broken pipe", "unexpected eof", "deadline exceeded", "i/o timeout", "server closed",
}

// IsTransient reports whether err is a transient transport blip worth retrying. A nil error, or a
// permanent fault (connection refused / no such host / unsupported scheme), is NOT transient.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	for _, sig := range transientSignals {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}
