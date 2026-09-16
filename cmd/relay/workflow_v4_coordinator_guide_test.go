package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4CoordinatorIntentIsStableAndCheckpointStaysPublic(t *testing.T) {
	work := t.TempDir()
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	pair := pairV4Test("head")
	path := filepath.Join(workflowV4CoordinatorTurnDir(work, scope), "allocation-intent.json")
	output := workflowV4CoordinatorCheckpointDir(work, scope, "allocate", "basis")
	first, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", pair, scope, "", output)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", pair, scope, "", output)
	if err != nil || second != first {
		t.Fatalf("unstable intent: first=%+v second=%+v err=%v", first, second, err)
	}
	public := filepath.Join(work, "ceremony", "public")
	if relative, err := filepath.Rel(public, first.OutputDir); err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("checkpoint output escaped public artifact root: %s", first.OutputDir)
	}
	changed := pair
	changed.Record.Digest.SHA256 = "sha256:" + strings.Repeat("3", 64)
	if _, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", changed, scope, "", output); err == nil {
		t.Fatal("retained intent was silently rebound to another predecessor")
	}
}

func TestWorkflowV4CoordinatorCheckpointCommandsUseMountedPaths(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{filepath.Join(work, "ceremony", "public"), filepath.Join(trust), filepath.Join(keys)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	online := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys}
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "p", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	intent := workflowV4CoordinatorIntent{Action: "allocate", Scope: scope, AttemptID: strings.Repeat("a", 32), At: "2026-09-16T00:00:00Z", OutputDir: workflowV4CoordinatorCheckpointDir(work, scope, "allocate", "basis")}
	head := pairV4Test("head")
	command, err := workflowV4CheckpointCommand(signer, online, head, intent, "allocate-v4", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{"checkpoint allocate-v4", "--artifact-root /work/ceremony/public", "--coordinator-signing-key /keys/signing.hex", "--attempt-id " + intent.AttemptID} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q lacks %q", joined, want)
		}
	}
}

func pairV4Test(seed string) transcript.SignedArtifactRefs {
	digest := func(s string) transcript.Digest {
		return transcript.Digest{SHA256: "sha256:" + strings.Repeat(s, 64), Blake2b256: "blake2b256:" + strings.Repeat(s, 64), Size: 10}
	}
	return transcript.SignedArtifactRefs{Record: transcript.ArtifactRef{Name: "checkpoints/" + seed + "/checkpoint.json", Digest: digest("a")}, Signature: transcript.ArtifactRef{Name: "checkpoints/" + seed + "/checkpoint.sig", Digest: digest("b")}}
}
