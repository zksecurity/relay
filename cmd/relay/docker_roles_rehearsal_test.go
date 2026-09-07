package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

// Local, opt-in three-participant phase1 rehearsal. Unlike the packaging smoke
// test, this computes and verifies real contributions through the Docker driver
// and PR18's coordinator launcher policy. It does not test object storage or
// phase2/final release. All generated identities are disposable rehearsal keys.
func TestDockerRolesTinyPhase1Rehearsal(t *testing.T) {
	if os.Getenv("RELAY_ROLE_REHEARSAL") != "1" {
		t.Skip("set RELAY_ROLE_REHEARSAL=1 and the role image variables")
	}
	online, contributor := os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), os.Getenv("RELAY_ROLE_OFFLINE_IMAGE")
	platform := os.Getenv("RELAY_ROLE_PLATFORM")
	work, private := privateRoleTestDir(t), privateRoleTestDir(t)
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	bound := client.BindHost(endpoint)
	coordinatorKeys := filepath.Join(private, "coordinator")
	if err := os.Mkdir(coordinatorKeys, 0o700); err != nil {
		t.Fatal(err)
	}
	coordinator := dockerRoleOptions{role: "coordinator", image: online, platform: platform, work: work, keys: coordinatorKeys}
	runCoordinator := func(command ...string) {
		t.Helper()
		args, err := dockerRoleArgs(coordinator, append([]string{"mpc-ceremony"}, command...), os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		if err := bound.Attached(os.Stdout, os.Stderr, args...); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	runCoordinator("rehearsal", "init", "--created-at", start.Format(time.RFC3339), "--out-dir", "/work/rehearsal")
	home := filepath.Join(work, "rehearsal")
	keys := filepath.Join(private, "fixture-keys")
	if err := os.Rename(filepath.Join(home, "keys"), keys); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(keys, "coordinator.ed25519.private.hex"), filepath.Join(coordinatorKeys, "coordinator.key")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "public")
	parent := filepath.Join(work, "candidates")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 3; index++ {
		id := fmt.Sprintf("participant-%02d", index)
		t.Logf("Computing %s in disposable contributor, then accepting via coordinator role container", id)
		config := access.ParticipantConfig{
			Schema: access.ParticipantConfigSchema, Phase: "phase1", Root: root,
			Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"), CoordinatorKey: filepath.Join(root, "coordinator-public-key.hex"),
			CeremonyBinary: "/usr/local/bin/mpc-ceremony", SigningKey: filepath.Join(keys, id+".ed25519.private.hex"), Environment: filepath.Join(home, "config", "environment.json"),
			CandidateParentDir: parent, PublishedBaseURL: "https://ceremony.example", PublishedBucket: "unused",
			ExecutionMode: dockerExecutionMode, DockerImage: contributor, DockerPlatform: platform, DockerCLI: "docker",
		}
		if err := config.Validate(); err != nil {
			t.Fatal(err)
		}
		driver := dockerDriverForParticipant(config)
		if err := driver.preflight(); err != nil {
			t.Fatal(err)
		}
		definition, err := driver.inspector().Definition()
		if err != nil {
			t.Fatal(err)
		}
		participant, err := driver.inspector().Participant(config.SigningKey)
		if err != nil {
			t.Fatal(err)
		}
		chainName := fmt.Sprintf("chain-%04d", index-1)
		chainPath := filepath.Join(root, "phase1", chainName+".json")
		chain, err := driver.inspector().Chain(chainPath, filepath.Join(root, "phase1", chainName+".sig"))
		if err != nil {
			t.Fatal(err)
		}
		o := participantRoleOptions(config, participant.ParticipantID)
		o.outDir = filepath.Join(parent, id)
		pos := position{definition: definition, chain: chain, chainPath: chainPath, nextID: id, nextIndex: index}
		contributed := start.Add(time.Duration(index*5) * time.Second)
		if err := runNextAt(o, pos, contributed); err != nil {
			t.Fatal(err)
		}
		if err := runErasureAt(o, contributed.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		runCoordinator("phase1", "verify",
			"--ceremony", "/work/rehearsal/public/ceremony.json", "--ceremony-signature", "/work/rehearsal/public/ceremony.sig",
			"--coordinator-public-key-file", "/work/rehearsal/public/coordinator-public-key.hex", "--transcript-dir", "/work/rehearsal/public",
			"--chain", "/work/rehearsal/public/phase1/"+chainName+".json", "--chain-signature", "/work/rehearsal/public/phase1/"+chainName+".sig",
			"--candidate-dir", "/work/candidates/"+id, "--coordinator-signing-key", "/keys/coordinator.key", "--accepted-at", contributed.Add(2*time.Second).Format(time.RFC3339))
		acceptedName := fmt.Sprintf("chain-%04d", index)
		accepted, err := driver.inspector().Chain(filepath.Join(root, "phase1", acceptedName+".json"), filepath.Join(root, "phase1", acceptedName+".sig"))
		if err != nil {
			t.Fatal(err)
		}
		if accepted.AcceptedCount() != index || accepted.Records[index-1].ParticipantID != id {
			t.Fatal("accepted chain mismatch")
		}
	}
	t.Log("PASS: three real Docker phase1 contributions, cleanup/erasure, and coordinator-role acceptance; no storage upload or phase2/final release")
}
