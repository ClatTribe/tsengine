package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/internal/mdm"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type fakeMDM struct {
	devices []deviceposture.Device
	err     error
}

func (f fakeMDM) Fetch(context.Context) ([]deviceposture.Device, mdm.Report, error) {
	return f.devices, mdm.Report{Provider: "kandji", Devices: len(f.devices)}, f.err
}

func off() *bool { b := false; return &b }
func on() *bool  { b := true; return &b }

// syncDevices makes the fleet a continuously-monitored surface: with an MDM configured, each pass
// reads it and an unencrypted laptop becomes a stored finding the Detector can turn into an incident.
func TestSyncDevices_FetchesAssessesStoresAndStamps(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", MDM: &platform.MDMConfig{Provider: platform.MDMKandji, BaseURL: "https://x.api.kandji.io", TokenRef: "sealed"}})
	n := 0
	var seen platform.Tenant
	svc := &Service{
		Store: st, NewID: func() string { n++; return itoa(n) },
		MDMFetcher: func(_ context.Context, tn platform.Tenant) (mdm.Fetcher, error) {
			seen = tn
			return fakeMDM{devices: []deviceposture.Device{
				{Name: "mac-alice", Owner: "alice@acme.io", DiskEncrypted: off()},
				{Name: "mac-bob", DiskEncrypted: on()},
			}}, nil
		},
	}
	out, ran := svc.syncDevices(ctx, "t1")
	if !ran {
		t.Fatal("the fleet was read → ran must be true so absence of a device finding is authoritative")
	}
	if seen.MDM == nil || seen.MDM.Provider != platform.MDMKandji {
		t.Errorf("the factory must receive the tenant carrying its MDM config, got %+v", seen.MDM)
	}
	if len(out) != 1 || out[0].RuleID != "deviceposture::disk-unencrypted" || out[0].ID == "" {
		t.Fatalf("exactly alice's disk should fire, with an id assigned: %+v", out)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) != 1 {
		t.Errorf("the finding must be persisted so it appears in issues: %d", len(stored))
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if _, ok := tn.PostureAssessed["deviceposture"]; !ok {
		t.Error("a scheduled sync must stamp the posture source, or a compliant fleet reads 'never checked'")
	}
}

// Every early return is a fleet NOT observed: ran=false, and nothing may resolve from its silence.
func TestSyncDevices_NotObservedIsNeverRan(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func() *Service{
		"no factory": func() *Service {
			st := store.NewMemory()
			_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", MDM: &platform.MDMConfig{Provider: platform.MDMKandji}})
			return &Service{Store: st, NewID: func() string { return "x" }}
		},
		"no MDM configured": func() *Service {
			st := store.NewMemory()
			_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
			return &Service{Store: st, NewID: func() string { return "x" },
				MDMFetcher: func(context.Context, platform.Tenant) (mdm.Fetcher, error) { return fakeMDM{}, nil }}
		},
		"factory refuses (credential unreadable)": func() *Service {
			st := store.NewMemory()
			_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", MDM: &platform.MDMConfig{Provider: platform.MDMKandji}})
			return &Service{Store: st, NewID: func() string { return "x" },
				MDMFetcher: func(context.Context, platform.Tenant) (mdm.Fetcher, error) { return nil, errors.New("no token") }}
		},
		"fetch fails (401)": func() *Service {
			st := store.NewMemory()
			_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", MDM: &platform.MDMConfig{Provider: platform.MDMKandji}})
			return &Service{Store: st, NewID: func() string { return "x" },
				MDMFetcher: func(context.Context, platform.Tenant) (mdm.Fetcher, error) {
					return fakeMDM{err: errors.New("HTTP 401")}, nil
				}}
		},
	}
	for name, mk := range cases {
		svc := mk()
		out, ran := svc.syncDevices(ctx, "t1")
		if ran || out != nil {
			t.Errorf("%s: must be (nil, false), got (%v, %v)", name, out, ran)
		}
		tn, _ := svc.Store.GetTenant(ctx, "t1")
		if _, ok := tn.PostureAssessed["deviceposture"]; ok {
			t.Errorf("%s: an unobserved fleet must NOT be stamped as assessed", name)
		}
	}
}

// A compliant fleet: nothing stored, but the pass DID observe it.
func TestSyncDevices_CompliantFleetIsRanWithNoFindings(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", MDM: &platform.MDMConfig{Provider: platform.MDMJamf}})
	svc := &Service{Store: st, NewID: func() string { return "x" },
		MDMFetcher: func(context.Context, platform.Tenant) (mdm.Fetcher, error) {
			return fakeMDM{devices: []deviceposture.Device{{Name: "ok", DiskEncrypted: on(), FirewallOn: on()}}}, nil
		}}
	out, ran := svc.syncDevices(ctx, "t1")
	if !ran || len(out) != 0 {
		t.Fatalf("compliant fleet → (empty, true), got (%v, %v)", out, ran)
	}
}
