package main

import (
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestWorkflowV4EnrollmentGrantRolesAreExplicit(t *testing.T) {
	for role, want := range map[string]string{
		"participant":     access.RoleParticipant,
		"release-signer":  access.RoleRelease,
		"auditor":         access.RoleAuditor,
		"public-witness":  access.RoleWitness,
		"mirror-operator": access.RoleMirror,
	} {
		got, err := workflowV4GrantRoleForEnrollment(role)
		if err != nil || got != want {
			t.Fatalf("role %s = %q, %v", role, got, err)
		}
	}
	if _, err := workflowV4GrantRoleForEnrollment("coordinator"); err == nil {
		t.Fatal("coordinator enrollment unexpectedly received a transport grant")
	}
}
