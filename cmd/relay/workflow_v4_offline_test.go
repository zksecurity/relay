package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func offlineFixture(t *testing.T) (string, state.ContentRef) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	object := workflowV4TestRef("checkpoints/head.json", "public checkpoint")
	ref := state.ContentRef{Name: object.Name, SHA256: object.Digest.SHA256, Size: object.Digest.Size}
	sig := ref
	sig.Name = "checkpoints/head.sig"
	root := state.Root{Schema: state.RootSchema, CeremonyID: "sha256:" + strings.Repeat("a", 64), Checkpoint: ref, CheckpointSignature: sig}
	manifest := workflowV4PublicSnapshot{Schema: "relay-public-snapshot-v1", Root: root, Files: []state.ContentRef{ref, sig}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, offlineSnapshotFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "objects", strings.TrimPrefix(ref.SHA256, "sha256:")), []byte("public checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, ref
}
func TestOfflineSnapshotBoundedPublicTransport(t *testing.T) {
	dir, ref := offlineFixture(t)
	s, err := openWorkflowV4OfflineStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	outputRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(outputRoot, "artifacts", "checkpoints", "final", "copy")
	if _, err = s.GetVersionedAtMost(store.Key(ref.SHA256), out, ref.Size-1); err == nil {
		t.Fatal("oversize object accepted")
	}
	if _, err = s.GetVersionedAtMost(store.Key(ref.SHA256), out, ref.Size); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "public checkpoint" {
		t.Fatal("public bytes not preserved", err)
	}
	if _, err = s.GetVersionedAtMost(store.Key(ref.SHA256), out, ref.Size); err == nil {
		t.Fatal("existing destination overwritten")
	}
}
func TestOfflineSnapshotRejectsUnexpectedPrivateFile(t *testing.T) {
	dir, _ := offlineFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "signing.hex"), []byte("synthetic marker, not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openWorkflowV4OfflineStore(dir); err == nil {
		t.Fatal("unexpected private file accepted")
	}
}
func TestOfflineSnapshotRejectsSymlinkObject(t *testing.T) {
	dir, ref := offlineFixture(t)
	path := filepath.Join(dir, "objects", strings.TrimPrefix(ref.SHA256, "sha256:"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, offlineSnapshotFile), path); err != nil {
		t.Fatal(err)
	}
	if _, err := openWorkflowV4OfflineStore(dir); err == nil {
		t.Fatal("symbolic link accepted")
	}
}
