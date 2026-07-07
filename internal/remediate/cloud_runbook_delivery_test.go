package remediate

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// captureFiler records the action it was asked to file (so a test can assert the runbook was delivered).
type captureFiler struct{ last *platform.Action }

func (c *captureFiler) FileTicket(_ context.Context, a platform.Action) error {
	cp := a
	c.last = &cp
	return nil
}

// TestDeliverer_CloudRunbookFilesTicketNotError: a cloud remediation whose class has no live connector
// write yet (here an open-security-group fix — sg_restrict_ingress) must DELIVER as an actionable ticket
// carrying its runbook, NOT error "no live write path". This completes the Respond breadth catalog (#984):
// before, approving one of the 8 named-but-gated classes at the desk failed on connector.Apply.
func TestDeliverer_CloudRunbookFilesTicketNotError(t *testing.T) {
	ctx := context.Background()
	filer := &captureFiler{}
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Ticket: filer}

	act := platform.Action{
		ID: "a-sg", TenantID: "t", Kind: platform.ActApplyConfig, Tier: tierApplyConfig,
		Payload: map[string]any{"remediation_type": rtypeSGRestrict, "target": "sg-0abc", "remediation": "aws ec2 revoke-security-group-ingress ..."},
	}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatalf("a cloud runbook remediation must deliver cleanly, got error: %v", err)
	}
	if filer.last == nil || filer.last.ID != "a-sg" {
		t.Fatal("the runbook remediation must be filed as a ticket for the human's team to execute")
	}
	if filer.last.Payload["remediation_type"] != rtypeSGRestrict {
		t.Errorf("the filed ticket must carry the runbook payload, got %+v", filer.last.Payload)
	}
}

// With no Filer configured, a cloud runbook remediation is a graceful recorded no-op (never a false
// "applied", never a hard error).
func TestDeliverer_CloudRunbookNoFilerIsGracefulNoop(t *testing.T) {
	ctx := context.Background()
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}}
	act := platform.Action{ID: "a-mfa", TenantID: "t", Kind: platform.ActApplyConfig, Tier: tierApplyConfig,
		Payload: map[string]any{"remediation_type": rtypeEnforceMFA, "target": "root"}}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatalf("no Filer → graceful no-op, got error: %v", err)
	}
}

// A LIVE-writable cloud class (s3_block_public_access) must NOT be caught by the runbook router — it falls
// through to the real connector write path. With no matching connection it errors (proving it took the
// connector path, not the ticket path), and the Filer is never touched.
func TestDeliverer_LiveStorageNotRoutedToTicket(t *testing.T) {
	ctx := context.Background()
	filer := &captureFiler{}
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Ticket: filer}
	act := platform.Action{ID: "a-s3", TenantID: "t", Kind: platform.ActApplyConfig, Tier: tierApplyConfig,
		FindingID: "f1", Payload: map[string]any{"remediation_type": rtypeS3Block, "target": "arn:aws:s3:::b"}}
	// no active AWS connection → the connector path errors; the point is it did NOT get filed as a ticket.
	_ = d.Apply(ctx, act)
	if filer.last != nil {
		t.Error("a live-writable storage remediation must NOT be routed to the ticket filer")
	}
}
