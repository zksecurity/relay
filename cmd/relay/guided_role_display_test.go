package main

import (
	"strings"
	"testing"
)

func TestGuidedSigningEnvironmentDisplay(t *testing.T) {
	for _, tc := range []struct {
		execution, context, role, want string
		invalid                        bool
	}{
		{"decision-signer", "participant", "participant", "Ceremony role: Participant", false},
		{"decision-signer", "coordinator", "", "Ceremony role: Coordinator", false},
		{"decision-signer", "", "participant", "Ceremony role: Participant", false},
		{"decision-signer", "", "public-witness", "Ceremony role: Witness", false},
		{"decision-signer", "mirror", "mirror-operator", "Ceremony role: Mirror", false},
		{"decision-signer", "participant", "public-witness", "", true},
		{"decision-signer", "", "", "Ceremony role: see signed record", false},
		{"decision-signer", "participant", "coordinator", "", true},
		{"participant", "coordinator", "", "", true},
		{"decision-signer", "unknown", "", "", true},
		{"participant", "", "", "Role: participant", false},
	} {
		var command []string
		if tc.role != "" {
			command = []string{"mpc-ceremony", "ops", "prepare-enrollment", "--role", tc.role}
		}
		got, err := guidedRoleDisplay(tc.execution, tc.context, command)
		if (err != nil) != tc.invalid || (!tc.invalid && !strings.Contains(got, tc.want)) {
			t.Fatalf("%+v: %s %v", tc, got, err)
		}
		if !tc.invalid && tc.execution == "decision-signer" && !strings.Contains(got, "Execution environment: Network-disabled signing container") {
			t.Fatal("missing environment label")
		}
	}
}
