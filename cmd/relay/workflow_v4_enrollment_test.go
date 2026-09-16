package main

import (
	"os"
	"path/filepath"
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

func TestWorkflowV4EnrollmentSourcePathsDistinguishLocalAndTransportLayouts(t *testing.T) {
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "canonical.json"), []byte("record"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := workflowV4EnrollmentSourcePaths(local, "participant-01")
	if err != nil {
		t.Fatal(err)
	}
	wantDisclosure := filepath.Join(local, "enrollments", "participant-01", "disclosure.txt")
	if paths["enrollment.json"] != filepath.Join(local, "canonical.json") || paths["disclosure.txt"] != wantDisclosure {
		t.Fatalf("local authoring layout = %#v", paths)
	}

	transport := t.TempDir()
	if err := os.WriteFile(filepath.Join(transport, "enrollment.json"), []byte("record"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err = workflowV4EnrollmentSourcePaths(transport, "participant-01")
	if err != nil {
		t.Fatal(err)
	}
	if paths["enrollment.json"] != filepath.Join(transport, "enrollment.json") || paths["disclosure.txt"] != filepath.Join(transport, "disclosure.txt") {
		t.Fatalf("transport layout = %#v", paths)
	}
	if err := os.WriteFile(filepath.Join(transport, "canonical.json"), []byte("duplicate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := workflowV4EnrollmentSourcePaths(transport, "participant-01"); err == nil {
		t.Fatal("accepted ambiguous mixed enrollment layout")
	}
}
