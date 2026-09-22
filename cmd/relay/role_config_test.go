package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
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

func TestDockerSetupDefaultsToReceiptMeasuredHostCompanion(t *testing.T) {
	root := t.TempDir()
	hostTool := filepath.Join(root, "mpc-ceremony")
	if err := os.WriteFile(hostTool, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tool-identity-receipt.env")
	writeTestToolIdentityReceipt(t, receiptPath, "rehearsal", hostTool)
	receipt, err := loadToolIdentityReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := dockerSetupMeasurementBinary([]string{"--execution-mode", "docker"}, receiptPath, dockerCeremonyBinary)
	if err != nil {
		t.Fatal(err)
	}
	if got != receipt.MPCCeremony.VerifiedPath {
		t.Fatalf("measurement binary = %q, want receipt path %q", got, receipt.MPCCeremony.VerifiedPath)
	}
	explicit := filepath.Join(root, "explicit-mpc-ceremony")
	got, err = dockerSetupMeasurementBinary([]string{"--ceremony-binary", explicit}, receiptPath, explicit)
	if err != nil || got != explicit {
		t.Fatalf("explicit measurement binary = %q, %v", got, err)
	}
}

func TestDockerParticipantNeverExecutesMeasuredHostCompanion(t *testing.T) {
	hostTool := "/opt/relay-kit/mpc-ceremony"
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, CeremonyBinary: hostTool,
		DockerImage: "sha256:" + strings.Repeat("a", 64), DockerPlatform: "linux/arm64", DockerCLI: "docker",
	}
	driver := dockerDriverForParticipant(config)
	if driver.ceremonyBinary != dockerCeremonyBinary {
		t.Fatalf("Docker execution binary = %q, want fixed %q", driver.ceremonyBinary, dockerCeremonyBinary)
	}
	args := strings.Join(driver.securityArgs(nil), " ")
	if strings.Contains(args, hostTool) || !strings.Contains(args, "--entrypoint "+dockerCeremonyBinary) {
		t.Fatalf("Docker security arguments did not enforce the fixed entrypoint: %s", args)
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
