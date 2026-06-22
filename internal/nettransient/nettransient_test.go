package nettransient

import (
	"errors"
	"net"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsTransient(t *testing.T) {
	transient := []error{timeoutErr{}, errors.New("read: connection reset by peer"), errors.New("write: broken pipe"), errors.New("unexpected EOF"), &net.OpError{Op: "dial", Err: timeoutErr{}}}
	for _, e := range transient {
		if !IsTransient(e) {
			t.Errorf("%v should be transient", e)
		}
	}
	permanent := []error{nil, errors.New("connection refused"), errors.New("no such host"), errors.New("unsupported protocol scheme")}
	for _, e := range permanent {
		if IsTransient(e) {
			t.Errorf("%v should NOT be transient", e)
		}
	}
}
