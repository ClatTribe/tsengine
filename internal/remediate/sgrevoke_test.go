package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// An open-to-the-internet security group finding on an AWS account that NAMES the group becomes a
// gated live revoke carrying the group id and the port; one that names no group, or sits on GCP,
// keeps the runbook ticket — and the two remediation_types never collide.
func TestProposeCloud_OpenSGPromotesToLiveRevokeOnlyWhenTheGroupIsNamed(t *testing.T) {
	aws := platform.Asset{ID: "c1", TenantID: "t1", ConnectionID: "aws1", Type: "cloud_account", Target: "aws", Meta: map[string]string{"provider": "aws"}}
	prowler := types.Finding{ID: "f1", RuleID: "prowler::ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", Severity: types.SeverityHigh,
		Title: "Security group sg-0abc12345 (web) allows ingress from the Internet (0.0.0.0/0) to TCP port 22", Endpoint: "sg-0abc12345"}
	act, ok := Propose(prowler, aws, gen())
	if !ok || act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig {
		t.Fatalf("named group on AWS must be a gated live mutation: %+v", act)
	}
	if act.Payload["remediation_type"] != rtypeSGRevoke || act.Payload["target"] != "sg-0abc12345" || act.Payload["port"] != 22 {
		t.Errorf("payload must carry the group and the port: %+v", act.Payload)
	}
	if rem, _ := act.Payload["remediation"].(string); !strings.Contains(rem, "ONLY the world-open") || !strings.Contains(rem, "port 22") {
		t.Errorf("the human must be told what is and is not touched: %q", rem)
	}
	if cloudRunbookRemediations[rtypeSGRevoke] {
		t.Fatal("the live type must NOT be in the runbook set, or the deliverer files a ticket instead of writing")
	}
	if !cloudRunbookRemediations[rtypeSGRestrict] {
		t.Fatal("the runbook type must stay a runbook")
	}

	// The CDR poller's finding shape names the group in the endpoint and the CIDR in the description.
	cdr := types.Finding{ID: "f2", RuleID: "cloudcdr::security_group_opened", Severity: types.SeverityHigh,
		Title: "Security group ingress opened to the world", Endpoint: "cloud:sg-0def67890",
		Description: `aws control-plane action: AuthorizeSecurityGroupIngress; detail {"groupId":"sg-0def67890","ipPermissions":{"items":[{"fromPort":3389,"toPort":3389,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}`}
	if act, _ := Propose(cdr, aws, gen()); act.Payload["remediation_type"] != rtypeSGRevoke || act.Payload["target"] != "sg-0def67890" {
		t.Errorf("a CDR-detected opening must promote too: %+v", act.Payload)
	}

	// No group named → the runbook ticket stands (revoking on a guessed group has a blast radius).
	unnamed := prowler
	unnamed.Title, unnamed.Endpoint = "A security group allows ingress from 0.0.0.0/0 to port 22", "aws"
	if act, _ := Propose(unnamed, aws, gen()); act.Payload["remediation_type"] != rtypeSGRestrict {
		t.Errorf("unnamed group must stay the runbook: %+v", act.Payload)
	}
	// GCP → runbook (no live firewall write path).
	gcp := aws
	gcp.Meta = map[string]string{"provider": "gcp"}
	if act, _ := Propose(prowler, gcp, gen()); act.Payload["remediation_type"] != rtypeSGRestrict {
		t.Errorf("GCP must stay the runbook: %+v", act.Payload)
	}
	// A finding naming no port carries none, and the text says every world-open rule is in scope.
	noport := prowler
	noport.RuleID, noport.Title = "prowler::ec2_securitygroup_default_open", "Default security group sg-0abc12345 is open to the internet"
	act, _ = Propose(noport, aws, gen())
	if _, has := act.Payload["port"]; has || !strings.Contains(act.Payload["remediation"].(string), "every ingress rule") {
		t.Errorf("no port → none carried and the scope stated: %+v", act.Payload)
	}
}
