package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

// TestDockerDriverWithRealCeremonyTool is opt-in because it requires Docker
// and the exact Linux mpc-ceremony image. It initializes its own tiny rehearsal
// with that image, then covers
// the real create/inspect/start/remove/absence-check path, followed by the real
// erasure attestation command in a second secret-free container.
func TestDockerDriverWithRealCeremonyTool(t *testing.T) {
	image := os.Getenv("RELAY_DOCKER_TEST_IMAGE")
	platform := os.Getenv("RELAY_DOCKER_TEST_PLATFORM")
	if image == "" {
		t.Skip("set RELAY_DOCKER_TEST_IMAGE")
	}
	if platform == "" {
		platform = "linux/amd64"
	}
	workspace := t.TempDir()
	bootstrap := &dockerDriver{
		image: image, platform: platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony",
		client: osDockerCommandClient{binary: "docker"}, now: time.Now,
	}
	bootstrapMounts := []dockerMount{{Source: workspace, Destination: "/work", ReadOnly: false}}
	if err := validateMountSources(bootstrapMounts); err != nil {
		t.Fatal(err)
	}
	initialize := bootstrap.baseRunArgs(true, bootstrapMounts)
	initialize = append(initialize, image, "rehearsal", "init",
		"--created-at", time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		"--out-dir", "/work/rehearsal")
	if err := bootstrap.client.Attached(os.Stdout, os.Stderr, initialize...); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(workspace, "rehearsal")
	root := filepath.Join(home, "public")
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, Phase: "phase1", Root: root,
		Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"),
		CoordinatorKey:     filepath.Join(root, "coordinator-public-key.hex"),
		CeremonyBinary:     "/usr/local/bin/mpc-ceremony",
		SigningKey:         filepath.Join(home, "keys", "participant-01.ed25519.private.hex"),
		Environment:        filepath.Join(home, "config", "environment.json"),
		CandidateParentDir: filepath.Join(home, "docker-driver-candidates"),
		PublishedBaseURL:   "https://ceremony.example", PublishedBucket: "unused",
		ExecutionMode: dockerExecutionMode, DockerImage: image, DockerPlatform: platform, DockerCLI: "docker",
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config.CandidateParentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := dockerDriverForParticipant(config)
	definition, err := driver.inspector().Definition()
	if err != nil {
		t.Fatal(err)
	}
	participant, err := driver.inspector().Participant(config.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(root, "phase1", "chain-0000.json")
	chainSignature := filepath.Join(root, "phase1", "chain-0000.sig")
	chain, err := driver.inspector().Chain(chainPath, chainSignature)
	if err != nil {
		t.Fatal(err)
	}
	o := participantRoleOptions(config, participant.ParticipantID)
	o.outDir = filepath.Join(config.CandidateParentDir, "candidate")
	pos := position{
		definition: definition, chain: chain, chainPath: chainPath,
		nextID: participant.ParticipantID, nextIndex: 1,
	}
	contributedAt := time.Now().UTC().Truncate(time.Second)
	if err := runNextAt(o, pos, contributedAt); err != nil {
		t.Fatal(err)
	}
	if err := runErasureAt(o, contributedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, name := range candidateFileNames {
		info, err := os.Lstat(filepath.Join(o.outDir, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("real Docker candidate %s: %v", name, err)
		}
	}
	coordinatorKey := filepath.Join(home, "keys", "coordinator.ed25519.private.hex")
	mounts := []dockerMount{
		{Source: root, Destination: "/relay/public", ReadOnly: false},
		{Source: o.outDir, Destination: "/relay/candidate", ReadOnly: true},
		{Source: coordinatorKey, Destination: "/relay/key/coordinator.key", ReadOnly: true},
	}
	if err := validateMountSources(mounts); err != nil {
		t.Fatal(err)
	}
	verify := driver.baseRunArgs(true, mounts)
	verify = append(verify, image,
		"phase1", "verify",
		"--ceremony", "/relay/public/ceremony.json",
		"--ceremony-signature", "/relay/public/ceremony.sig",
		"--coordinator-public-key-file", "/relay/public/coordinator-public-key.hex",
		"--transcript-dir", "/relay/public",
		"--chain", "/relay/public/phase1/chain-0000.json",
		"--chain-signature", "/relay/public/phase1/chain-0000.sig",
		"--candidate-dir", "/relay/candidate",
		"--coordinator-signing-key", "/relay/key/coordinator.key",
		"--accepted-at", contributedAt.Add(2*time.Second).Format(time.RFC3339),
	)
	if err := driver.client.Attached(os.Stdout, os.Stderr, verify...); err != nil {
		t.Fatal(err)
	}
	accepted, err := driver.inspector().Chain(
		filepath.Join(root, "phase1", "chain-0001.json"),
		filepath.Join(root, "phase1", "chain-0001.sig"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.AcceptedCount() != 1 || accepted.Records[0].ParticipantID != participant.ParticipantID {
		t.Fatalf("accepted chain does not contain the Docker contribution: %#v", accepted.Records)
	}
}
