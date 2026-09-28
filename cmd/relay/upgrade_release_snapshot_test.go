package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestUpgradeAdmitsOnlyCompletedCoordinatorReleaseSnapshot(t *testing.T) {
	work := t.TempDir()
	p := guidedProfile{Role: "coordinator", Work: work}
	digest := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	ceremonyID := "sha256:" + strings.Repeat("1", 64)
	reviewBytes, sigBytes := []byte("signed review checkpoint"), []byte("review signature")
	reviewName, sigName := "checkpoints/review/checkpoint.json", "checkpoints/review/checkpoint.sig"
	reviewRef := transcript.ArtifactRef{Name: reviewName, Digest: transcript.Digest{SHA256: digest(reviewBytes), Size: int64(len(reviewBytes))}}
	sigRef := transcript.ArtifactRef{Name: sigName, Digest: transcript.Digest{SHA256: digest(sigBytes), Size: int64(len(sigBytes))}}
	for name, raw := range map[string][]byte{reviewName: reviewBytes, sigName: sigBytes} {
		path := filepath.Join(work, "ceremony", "public", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	refs := transcript.SignedArtifactRefs{Record: reviewRef, Signature: sigRef}
	manifest := workflowV4PublicSnapshot{Schema: "relay-public-snapshot-v1", Root: state.Root{Schema: state.RootSchema, CeremonyID: ceremonyID, Checkpoint: state.ContentRef{Name: reviewName, SHA256: reviewRef.Digest.SHA256, Size: reviewRef.Digest.Size}, CheckpointSignature: state.ContentRef{Name: sigName, SHA256: sigRef.Digest.SHA256, Size: sigRef.Digest.Size}}, Files: []state.ContentRef{{Name: reviewName, SHA256: reviewRef.Digest.SHA256, Size: reviewRef.Digest.Size}, {Name: sigName, SHA256: sigRef.Digest.SHA256, Size: sigRef.Digest.Size}}}
	review := transcript.CheckpointInspectionV4{CheckpointRefs: refs}
	review.Checkpoint.CeremonyID = ceremonyID
	review.Checkpoint.Transition.Kind = "release-review-recorded"
	review.Checkpoint.Progress.ReleaseReview = &refs
	final := transcript.CheckpointInspectionV4{}
	final.Checkpoint.CeremonyID = ceremonyID
	final.Checkpoint.Transition.Kind = "final-release-recorded"
	final.Checkpoint.Progress.FinalRelease = &refs
	final.Checkpoint.PreviousCheckpoint = &refs
	accepted := map[string]transcript.CheckpointInspectionV4{reviewName: review, "checkpoints/final/checkpoint.json": final}
	public := map[string]transcript.ArtifactRef{reviewName: reviewRef, sigName: sigRef}
	manifestName := "workflow-v4/coordinator/release/snapshot-manifest.json"
	manifestPath := filepath.Join(work, filepath.FromSlash(manifestName))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0700); err != nil {
		t.Fatal(err)
	}
	inventory := upgradeInventory{Files: []upgradeInventoryFile{{Name: "ceremony/public/" + reviewName, SHA256: strings.TrimPrefix(reviewRef.Digest.SHA256, "sha256:"), Size: reviewRef.Digest.Size}, {Name: "ceremony/public/" + sigName, SHA256: strings.TrimPrefix(sigRef.Digest.SHA256, "sha256:"), Size: sigRef.Digest.Size}}}
	write := func(raw []byte) upgradeInventory {
		t.Helper()
		if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		copy := inventory
		copy.Files = append(append([]upgradeInventoryFile(nil), inventory.Files...), upgradeInventoryFile{Name: manifestName, SHA256: strings.TrimPrefix(digest(raw), "sha256:"), Size: int64(len(raw))})
		return copy
	}
	encode := func(m workflowV4PublicSnapshot) []byte {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	inv := write(encode(manifest))
	if ok, err := upgradeCompletedReleaseSnapshotManifest(p, inv, accepted, public); err != nil || !ok {
		t.Fatalf("completed H snapshot rejected: %v", err)
	}
	if err := upgradeCheckCleanFiles(p, inv, accepted, public); err != nil {
		t.Fatalf("completed H snapshot blocks clean exit: %v", err)
	}
	checkRejected := func(label string, inv upgradeInventory, p guidedProfile, accepted map[string]transcript.CheckpointInspectionV4, public map[string]transcript.ArtifactRef) {
		t.Helper()
		if _, err := upgradeCompletedReleaseSnapshotManifest(p, inv, accepted, public); err == nil {
			t.Fatalf("%s accepted", label)
		}
	}
	bad := manifest
	bad.Root.CheckpointSignature.SHA256 = digest([]byte("different signature"))
	checkRejected("wrong root signature", write(encode(bad)), p, accepted, public)
	bad = manifest
	bad.Files = append([]state.ContentRef(nil), manifest.Files...)
	bad.Files[0].SHA256 = digest([]byte("changed file"))
	checkRejected("changed file", write(encode(bad)), p, accepted, public)
	bad = manifest
	bad.Files = append([]state.ContentRef(nil), manifest.Files[1:]...)
	checkRejected("missing root checkpoint", write(encode(bad)), p, accepted, public)
	bad = manifest
	bad.Root.CeremonyID = "sha256:" + strings.Repeat("2", 64)
	checkRejected("wrong ceremony", write(encode(bad)), p, accepted, public)
	checkRejected("duplicate JSON field", write([]byte(`{"schema":"relay-public-snapshot-v1","schema":"relay-public-snapshot-v1"}`)), p, accepted, public)
	checkRejected("trailing JSON", write(append(encode(manifest), []byte(` {}`)...)), p, accepted, public)
	inv = write(encode(manifest))
	withoutFinal := map[string]transcript.CheckpointInspectionV4{reviewName: review}
	checkRejected("no signed final release", inv, p, withoutFinal, public)
	checkRejected("unauthenticated file", inv, p, accepted, map[string]transcript.ArtifactRef{reviewName: reviewRef})
	otherRole := p
	otherRole.Role = "release-signer"
	checkRejected("other role", inv, otherRole, accepted, public)
	inv.Files = append(inv.Files, upgradeInventoryFile{Name: "workflow-v4/coordinator/release/grants/grant.json", SHA256: strings.Repeat("a", 64), Size: 1})
	if err := upgradeCheckCleanFiles(p, inv, accepted, public); err == nil || !strings.Contains(err.Error(), "release handoff is still retained") {
		t.Fatalf("unresolved grant accepted beside completed H manifest: %v", err)
	}
}
