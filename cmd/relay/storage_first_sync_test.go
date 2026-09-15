package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func storageFirstSyncFiles(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, "ceremony.json"), filepath.Join(root, "ceremony.sig"),
		filepath.Join(root, "coordinator.hex"), filepath.Join(root, "mpc-ceremony"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("test"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1], paths[2], paths[3], filepath.Join(root, "workspace")
}

func storageFirstSyncBaseArgs(t *testing.T) []string {
	t.Helper()
	ceremony, signature, key, proofTool, workspace := storageFirstSyncFiles(t)
	return []string{
		"--ceremony", ceremony, "--ceremony-signature", signature,
		"--coordinator-key", key, "--ceremony-id", "sha256:" + strings.Repeat("1", 64),
		"--workspace", workspace, "--proof-tool", proofTool,
		"--role", "participant", "--identity", "participant-1",
		"--public-url", "https://ceremony.example",
	}
}

func acceptStorageFirstDefinition(inspector transcript.Inspector) (transcript.Definition, error) {
	return transcript.Definition{CeremonyID: "sha256:" + strings.Repeat("1", 64)}, nil
}

func TestAdvancedStorageFirstSyncPrintsOnlyRoleRelevantAuthenticatedSlots(t *testing.T) {
	args := storageFirstSyncBaseArgs(t)
	var output bytes.Buffer
	called := false
	syncFn := func(objects storagefirst.ObjectStore, verifier storagefirst.Verifier, highWater storagefirst.HighWater, ceremonyID, tempParent string) (storagefirst.Snapshot, error) {
		called = true
		client, ok := objects.(store.Client)
		if !ok || client.PublicBaseURL != "https://ceremony.example" || client.Bucket != "" || client.NoSign {
			t.Fatalf("unexpected public client: %#v", objects)
		}
		if _, ok := verifier.(storagefirst.ProofToolVerifier); !ok {
			t.Fatalf("unexpected verifier: %T", verifier)
		}
		if ceremonyID != "sha256:"+strings.Repeat("1", 64) || tempParent != args[9] {
			t.Fatalf("unexpected sync scope: %q %q", ceremonyID, tempParent)
		}
		position := state.CheckpointPosition{Sequence: 2, Digest: "sha256:" + strings.Repeat("2", 64), PhaseHeads: map[string]state.PhaseHeadPosition{"phase1": {Index: 0, Digest: "sha256:" + strings.Repeat("a", 64)}}}
		return storagefirst.Snapshot{Checkpoint: storagefirst.Checkpoint{
			Position: position, Transition: "phase1-outbound-published", ParticipantID: "participant-1",
			Slots: []storagefirst.Slot{
				{Kind: "receipt", Phase: "phase1", Index: 1, IdentityID: "participant-1", AttemptID: "mine", Status: "pending", ManifestKey: "mine/manifest.json"},
				{Kind: "receipt", Phase: "phase1", Index: 2, IdentityID: "participant-2", AttemptID: "other", Status: "pending", ManifestKey: "other/manifest.json"},
			},
		}}, nil
	}
	definitionFn := func(inspector transcript.Inspector) (transcript.Definition, error) {
		if inspector.Executable != args[11] || inspector.CeremonyPath != args[1] || inspector.CeremonySignaturePath != args[3] || inspector.CoordinatorPublicKeyPath != args[5] {
			t.Fatalf("unexpected proof-tool inspector: %+v", inspector)
		}
		return acceptStorageFirstDefinition(inspector)
	}
	if err := runStorageFirstSyncWith(args, &output, syncFn, definitionFn); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("synchronizer was not called")
	}
	text := output.String()
	for _, want := range []string{"authenticated storage-first ceremony state", "sequence: 2", "stage: phase1-outbound-published", "attempt=mine"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "participant-2") || strings.Contains(text, "attempt=other") {
		t.Fatalf("participant saw another role's slot:\n%s", text)
	}
}

func TestAdvancedStorageFirstSyncBuildsAuthenticatedStorageClient(t *testing.T) {
	args := storageFirstSyncBaseArgs(t)
	args = args[:len(args)-2]
	args = append(args, "--endpoint", "https://storage.example", "--bucket", "published", "--profile", "relay", "--region", "auto")
	syncFn := func(objects storagefirst.ObjectStore, _ storagefirst.Verifier, _ storagefirst.HighWater, _, _ string) (storagefirst.Snapshot, error) {
		client := objects.(store.Client)
		if client.Endpoint != "https://storage.example" || client.Bucket != "published" || client.Profile != "relay" || client.Region != "auto" || client.PublicBaseURL != "" {
			t.Fatalf("unexpected authenticated client: %+v", client)
		}
		return storagefirst.Snapshot{Checkpoint: storagefirst.Checkpoint{Position: state.CheckpointPosition{Digest: "sha256:" + strings.Repeat("2", 64), PhaseHeads: map[string]state.PhaseHeadPosition{"phase1": {Digest: "sha256:" + strings.Repeat("a", 64)}}}}}, nil
	}
	if err := runStorageFirstSyncWith(args, &bytes.Buffer{}, syncFn, acceptStorageFirstDefinition); err != nil {
		t.Fatal(err)
	}
}

func TestAdvancedStorageFirstSyncPrintsNothingWhenAuthenticationFails(t *testing.T) {
	var output bytes.Buffer
	err := runStorageFirstSyncWith(storageFirstSyncBaseArgs(t), &output, func(storagefirst.ObjectStore, storagefirst.Verifier, storagefirst.HighWater, string, string) (storagefirst.Snapshot, error) {
		return storagefirst.Snapshot{}, errors.New("bad checkpoint signature")
	}, acceptStorageFirstDefinition)
	if err == nil || !strings.Contains(err.Error(), "bad checkpoint signature") {
		t.Fatalf("err=%v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("unauthenticated output was printed: %q", output.String())
	}
}

func TestAdvancedStorageFirstSyncRequiresOneStorageSourceAndRole(t *testing.T) {
	base := storageFirstSyncBaseArgs(t)
	for name, mutate := range map[string]func([]string) []string{
		"both sources": func(args []string) []string {
			return append(args, "--endpoint", "https://storage.example", "--bucket", "bucket", "--profile", "profile")
		},
		"missing participant identity": func(args []string) []string {
			for i := range args {
				if args[i] == "--identity" {
					return append(args[:i], args[i+2:]...)
				}
			}
			return args
		},
	} {
		t.Run(name, func(t *testing.T) {
			args := mutate(append([]string(nil), base...))
			if err := runStorageFirstSyncWith(args, &bytes.Buffer{}, storagefirst.Sync, acceptStorageFirstDefinition); err == nil {
				t.Fatal("invalid command accepted")
			}
		})
	}
}

func TestAdvancedDispatchRecognizesStorageFirstSync(t *testing.T) {
	err := runAdvanced([]string{"storage-first-sync"})
	if err == nil || !strings.Contains(err.Error(), "--ceremony is required") {
		t.Fatalf("storage-first-sync was not dispatched to its flag validation: %v", err)
	}
}

func TestAdvancedStorageFirstSyncRejectsCeremonyIDMismatchBeforeSync(t *testing.T) {
	called := false
	err := runStorageFirstSyncWith(storageFirstSyncBaseArgs(t), &bytes.Buffer{}, func(storagefirst.ObjectStore, storagefirst.Verifier, storagefirst.HighWater, string, string) (storagefirst.Snapshot, error) {
		called = true
		return storagefirst.Snapshot{}, nil
	}, func(transcript.Inspector) (transcript.Definition, error) {
		return transcript.Definition{CeremonyID: "sha256:" + strings.Repeat("2", 64)}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("storage sync ran for a mismatched ceremony definition")
	}
}
