package cloudgraph

import "testing"

// A secret-access edge must let the path enumerator discover lateral movement:
// internet → (reach) compute → (runs_as) low-priv principal → (secret_access) privileged principal.
func TestSecretAccess_EnablesLateralMovementPath(t *testing.T) {
	inv := Inventory{
		AccountID: "acct", Provider: "aws",
		Resources: []InvResource{
			{ID: InternetID, Kind: KindNetwork},
			{ID: "ec2-web", Kind: KindResource, Type: "AWS::EC2::Instance"},
			{ID: "role-web", Kind: KindPrincipal, Type: "AWS::IAM::Role"},
			{ID: "role-admin", Kind: KindPrincipal, Type: "AWS::IAM::Role", Privileged: true},
			{ID: "secret-1", Kind: KindResource, Type: "AWS::SecretsManager::Secret"},
		},
		Reaches: []InvReach{{From: InternetID, To: "ec2-web"}},
		RunsAs:  []InvRunsAs{{Compute: "ec2-web", Principal: "role-web"}},
		// role-web can read secret-1, which holds role-admin's long-lived credential
		Secrets: []InvSecretAccess{{Principal: "role-web", Secret: "secret-1", Yields: "role-admin"}},
	}
	s := Ingest(inv)

	// the secret_access edge exists, names the secret, and points to the privileged principal
	var found *Edge
	for i := range s.Edges {
		if s.Edges[i].Kind == EdgeSecretAccess {
			found = &s.Edges[i]
		}
	}
	if found == nil || found.From != "role-web" || found.To != "role-admin" {
		t.Fatalf("expected role-web →(secret_access) role-admin edge, got %+v", found)
	}
	if found.Detail != "via secret secret-1" {
		t.Errorf("edge should name the secret in Detail, got %q", found.Detail)
	}

	// a path from the internet to the privileged identity must now exist (it didn't without the edge)
	paths := s.FindPaths(InternetID, PrivilegedIdentity, AllAttackEdges, 8, 10)
	if len(paths) == 0 {
		t.Fatal("internet → privileged-identity path should be discoverable via the secret_access edge")
	}

	// round-trip: ToInventory recovers the secret-access edge (including the secret id)
	rt := s.ToInventory()
	if len(rt.Secrets) != 1 || rt.Secrets[0].Yields != "role-admin" || rt.Secrets[0].Secret != "secret-1" {
		t.Errorf("ToInventory should round-trip the secret-access edge, got %+v", rt.Secrets)
	}
}
