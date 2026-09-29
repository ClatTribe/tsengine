package cloudprobe

import (
	"context"
	"errors"
	"testing"

	pt "google.golang.org/api/policytroubleshooter/v1"
)

type fakeTroubleshoot struct {
	access  string
	err     error
	gotReq  *pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyRequest
	nilResp bool
}

func (f *fakeTroubleshoot) Troubleshoot(_ context.Context, req *pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyRequest) (*pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyResponse, error) {
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	if f.nilResp {
		return nil, nil
	}
	return &pt.GoogleCloudPolicytroubleshooterV1TroubleshootIamPolicyResponse{Access: f.access}, nil
}

func gcpSimWith(f *fakeTroubleshoot) *GCPSimulator {
	return &GCPSimulator{newAPI: func(context.Context) (gcpTroubleshootAPI, error) { return f, nil }}
}

func TestGCPSimulate_AccessStateMapping(t *testing.T) {
	cases := []struct {
		access      string
		wantAllowed bool
		wantKnown   bool
	}{
		{"GRANTED", true, true},
		{"NOT_GRANTED", false, true}, // a DECIDED deny — the GCP twin of AWS implicit deny
		{"UNKNOWN_CONDITIONAL", false, false},
		{"UNKNOWN_INFO_DENIED", false, false},
		{"ACCESS_STATE_UNSPECIFIED", false, false},
		{"SOMETHING_NEW", false, false},
	}
	for _, c := range cases {
		s := gcpSimWith(&fakeTroubleshoot{access: c.access})
		d, err := s.Simulate(context.Background(), "sa@proj.iam.gserviceaccount.com",
			"storage.buckets.setIamPolicy", "//storage.googleapis.com/projects/_/buckets/b")
		if err != nil {
			t.Fatalf("%s: unexpected err %v", c.access, err)
		}
		if d.Allowed != c.wantAllowed || d.Known != c.wantKnown {
			t.Fatalf("%s: got allowed=%v known=%v want allowed=%v known=%v",
				c.access, d.Allowed, d.Known, c.wantAllowed, c.wantKnown)
		}
	}
}

func TestGCPSimulate_TupleIsForwarded(t *testing.T) {
	f := &fakeTroubleshoot{access: "GRANTED"}
	s := gcpSimWith(f)
	_, _ = s.Simulate(context.Background(), "alice@example.com", "compute.instances.get",
		"//compute.googleapis.com/projects/p/zones/z/instances/i")
	at := f.gotReq.AccessTuple
	if at == nil || at.Principal != "alice@example.com" || at.Permission != "compute.instances.get" ||
		at.FullResourceName != "//compute.googleapis.com/projects/p/zones/z/instances/i" {
		t.Fatalf("tuple not forwarded verbatim: %+v", at)
	}
}

func TestGCPSimulate_UnderSpecifiedTupleRefused(t *testing.T) {
	f := &fakeTroubleshoot{access: "GRANTED"}
	s := gcpSimWith(f)
	// Missing resource — GCP requires all three; must refuse WITHOUT calling the API.
	d, _ := s.Simulate(context.Background(), "alice@example.com", "compute.instances.get", "")
	if d.Known {
		t.Fatal("an under-specified tuple must be unknown, not a decision")
	}
	if f.gotReq != nil {
		t.Fatal("must not call the API on an under-specified tuple")
	}
}

func TestGCPSimulate_CallFailureIsUnknownNeverDeny(t *testing.T) {
	s := gcpSimWith(&fakeTroubleshoot{err: errors.New("403 missing troubleshoot permission")})
	d, err := s.Simulate(context.Background(), "a@b.com", "x.y", "//r")
	if err == nil {
		t.Fatal("want the error surfaced")
	}
	if d.Known {
		t.Fatal("a call failure must be UNKNOWN, never a deny (would close a live path)")
	}
}

func TestGCPSimulate_NilResponseUnknown(t *testing.T) {
	s := gcpSimWith(&fakeTroubleshoot{nilResp: true})
	d, _ := s.Simulate(context.Background(), "a@b.com", "x.y", "//r")
	if d.Known {
		t.Fatal("a nil/empty response must be unknown")
	}
}
