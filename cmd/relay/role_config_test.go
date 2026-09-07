package main

import (
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestFormatParticipantAssignment(t *testing.T) {
	phase1Position := uint8(3)
	output := formatParticipantAssignment(
		transcript.Definition{
			CeremonyID: "sha256:" + strings.Repeat("a", 64),
			Mode:       "production",
		},
		transcript.ParticipantInspection{
			ParticipantID:        "participant-03",
			KeyID:                "participant-03-key",
			PublicKeyFingerprint: "sha256:" + strings.Repeat("b", 64),
			Phase1Position:       &phase1Position,
		},
		"phase1",
		"/ceremony/config/participant-phase1.json",
	)

	for _, expected := range []string{
		"configured participant participant-03 for phase1",
		"ceremony: sha256:" + strings.Repeat("a", 64) + " (production)",
		"key id: participant-03-key",
		"fingerprint: sha256:" + strings.Repeat("b", 64),
		"phase1 position: 3",
		"phase2 position: not scheduled",
		"profile: /ceremony/config/participant-phase1.json",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("assignment output missing %q:\n%s", expected, output)
		}
	}
}

func TestDockerFlagsRequireExplicitDockerMode(t *testing.T) {
	for _, name := range []string{"docker-image", "docker-platform", "docker-cli"} {
		args := []string{"--" + name, "value"}
		err := rejectDockerFlagsWithoutDockerMode(args, nativeExecutionMode)
		if err == nil || !strings.Contains(err.Error(), "requires --execution-mode docker") {
			t.Fatalf("--%s with native mode error = %v", name, err)
		}
	}
	if err := rejectDockerFlagsWithoutDockerMode(
		[]string{"--docker-image=sha256:" + strings.Repeat("a", 64)}, dockerExecutionMode,
	); err != nil {
		t.Fatalf("explicit Docker mode rejected Docker flag: %v", err)
	}
}
