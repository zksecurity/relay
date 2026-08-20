package main

import (
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/store"
)

func TestCommandNamespacesRejectMissingAndUnknownSubcommands(t *testing.T) {
	tests := []struct {
		name string
		run  func([]string) error
		want string
	}{
		{"coordinator missing", runCoordinator, "coordinator requires"},
		{"coordinator unknown", runCoordinator, "unknown coordinator command"},
		{"ceremony missing", runCeremony, "ceremony requires"},
		{"ceremony unknown", runCeremony, "unknown ceremony command"},
		{"participant missing", runParticipant, "participant requires"},
		{"participant unknown", runParticipant, "unknown participant command"},
		{"witness missing", runWitness, "witness requires"},
		{"witness unknown", runWitness, "unknown witness command"},
		{"mirror missing", runMirror, "mirror requires"},
		{"mirror unknown", runMirror, "unknown mirror command"},
		{"auditor missing", runAuditor, "auditor requires"},
		{"auditor unknown", runAuditor, "unknown auditor command"},
		{"release missing", runRelease, "release requires"},
		{"release unknown", runRelease, "unknown release command"},
		{"advanced missing", runAdvanced, "advanced requires"},
		{"advanced unknown", runAdvanced, "unknown advanced command"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []string(nil)
			if strings.Contains(test.name, "unknown") {
				args = []string{"unknown"}
			}
			err := test.run(args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestRoleRoutingAllowsAuthenticatedConfigOrExplicitEndpoint(t *testing.T) {
	base := roleOpts{
		root: "/ceremony", definition: "/ceremony/ceremony.json",
		definitionSig: "/ceremony/ceremony.sig", coordinatorKey: "/trusted/coordinator.hex",
		phase: "phase1", client: store.Client{Bucket: "published"},
	}
	if err := checkRole(base); err == nil || !strings.Contains(err.Error(), "--endpoint") {
		t.Fatalf("missing routing error = %v", err)
	}
	base.client.PublicBaseURL = "https://ceremony.example"
	if err := checkRole(base); err != nil {
		t.Fatalf("public HTTPS role routing rejected: %v", err)
	}
}
