package storagefirst

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

type memoryObjects map[string][]byte

func (m memoryObjects) GetVersionedAtMost(key, local string, maximum int64) (store.ObjectVersion, error) {
	raw, ok := m[key]
	if !ok {
		return store.ObjectVersion{}, os.ErrNotExist
	}
	if int64(len(raw)) > maximum {
		return store.ObjectVersion{}, errors.New("too large")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return store.ObjectVersion{}, err
	}
	if err := os.WriteFile(local, raw, 0o600); err != nil {
		return store.ObjectVersion{}, err
	}
	return store.ObjectVersion{ETag: "etag", Size: int64(len(raw))}, nil
}

type verifierFake struct {
	byDigest       map[string]Checkpoint
	transitions    int
	rejectEdge     bool
	rejectEvidence bool
	evidence       EvidenceVerification
}

func (v *verifierFake) VerifyCheckpoint(checkpointPath, _ string) (Checkpoint, error) {
	raw, err := os.ReadFile(checkpointPath)
	if err != nil {
		return Checkpoint{}, err
	}
	digest := sum(raw)
	checkpoint, ok := v.byDigest[digest]
	if !ok {
		return Checkpoint{}, errors.New("unknown checkpoint")
	}
	return checkpoint, nil
}

func (v *verifierFake) VerifyTransition(_, _, _, _ string) error {
	v.transitions++
	if v.rejectEdge {
		return errors.New("illegal edge")
	}
	return nil
}

func (v *verifierFake) VerifyEvidence(_, _, _ string) (EvidenceVerification, error) {
	if v.rejectEvidence {
		return EvidenceVerification{}, errors.New("bad stored evidence")
	}
	return v.evidence, nil
}

type highWaterFake struct {
	position state.CheckpointPosition
	exists   bool
	fail     bool
}

func (h *highWaterFake) Seen() (state.CheckpointPosition, bool, error) {
	return h.position, h.exists, nil
}
func (h *highWaterFake) Check(candidate state.CheckpointPosition) error {
	if h.exists && candidate.Sequence == h.position.Sequence && candidate.Digest != h.position.Digest {
		return errors.New("fork")
	}
	return nil
}
func (h *highWaterFake) Record(candidate state.CheckpointPosition) error {
	if h.fail {
		return errors.New("disk full")
	}
	h.position, h.exists = candidate, true
	return nil
}

func sum(raw []byte) string {
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func ref(name string, raw []byte) state.ContentRef {
	return state.ContentRef{Name: name, SHA256: sum(raw), Size: int64(len(raw))}
}

func fixture(t *testing.T) (memoryObjects, *verifierFake, string) {
	t.Helper()
	ceremonyID := "sha256:" + strings.Repeat("1", 64)
	cp0, sig0 := []byte(`{"sequence":0}`), []byte("sig0")
	cp1, sig1 := []byte(`{"sequence":1}`), []byte("sig1")
	evidence := []byte("accepted evidence")
	evidenceRef := ref("phase1/evidence.bin", evidence)
	r0 := SignedRef{ref("checkpoints/0.json", cp0), ref("checkpoints/0.sig", sig0)}
	r1 := SignedRef{ref("checkpoints/1.json", cp1), ref("checkpoints/1.sig", sig1)}
	p0 := state.CheckpointPosition{Sequence: 0, Digest: r0.Checkpoint.SHA256, PhaseHeads: map[string]state.PhaseHeadPosition{"phase1": {Digest: "sha256:" + strings.Repeat("a", 64)}}}
	p1 := state.CheckpointPosition{Sequence: 1, Digest: r1.Checkpoint.SHA256, PreviousDigest: p0.Digest, PhaseHeads: p0.PhaseHeads}
	root := state.Root{Schema: state.RootSchema, CeremonyID: ceremonyID, Checkpoint: r1.Checkpoint, CheckpointSignature: r1.Signature}
	rootRaw, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	objects := memoryObjects{
		state.RootKey(ceremonyID):       rootRaw,
		store.Key(r0.Checkpoint.SHA256): cp0, store.Key(r0.Signature.SHA256): sig0,
		store.Key(r1.Checkpoint.SHA256): cp1, store.Key(r1.Signature.SHA256): sig1,
		store.Key(evidenceRef.SHA256): evidence,
	}
	verifier := &verifierFake{byDigest: map[string]Checkpoint{
		p0.Digest: {Position: p0, Artifacts: []state.ContentRef{evidenceRef}},
		p1.Digest: {Position: p1, Previous: &r0, Transition: "phase1-outbound-published", Artifacts: []state.ContentRef{evidenceRef}},
	}, evidence: EvidenceVerification{CeremonyID: ceremonyID, Sequence: 1, Digest: p1.Digest, TransitionKind: "phase1-outbound-published", FullyVerified: true}}
	return objects, verifier, ceremonyID
}

func TestSyncRejectsIncompleteEvidenceBeforeAdvancingHighWater(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	verifier.rejectEvidence = true
	highWater := &highWaterFake{}
	_, err := Sync(objects, verifier, highWater, ceremonyID, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "bad stored evidence") {
		t.Fatalf("err=%v", err)
	}
	if highWater.exists {
		t.Fatal("unverified evidence advanced high-water")
	}
}

func TestSyncReturningWorkspaceRecordsOnlyNewChildren(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	var p0 state.CheckpointPosition
	for _, checkpoint := range verifier.byDigest {
		if checkpoint.Position.Sequence == 0 {
			p0 = checkpoint.Position
		}
	}
	highWater := &highWaterFake{position: p0, exists: true}
	if _, err := Sync(objects, verifier, highWater, ceremonyID, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if highWater.position.Sequence != 1 {
		t.Fatalf("high-water sequence=%d, want 1", highWater.position.Sequence)
	}
}

func TestSyncFreshWorkspaceWalksAndRecordsAllAncestry(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	highWater := &highWaterFake{}
	snapshot, err := Sync(objects, verifier, highWater, ceremonyID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Checkpoint.Position.Sequence != 1 || snapshot.Checked != 2 || verifier.transitions != 1 {
		t.Fatalf("snapshot=%+v transitions=%d", snapshot, verifier.transitions)
	}
	if !highWater.exists || highWater.position.Digest != snapshot.Checkpoint.Position.Digest {
		t.Fatal("latest authenticated checkpoint was not recorded")
	}
}

func TestSyncRejectsIllegalTransitionBeforeAdvancingLatest(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	verifier.rejectEdge = true
	highWater := &highWaterFake{}
	_, err := Sync(objects, verifier, highWater, ceremonyID, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "illegal edge") {
		t.Fatalf("err=%v", err)
	}
	if highWater.position.Sequence != 0 {
		t.Fatal("illegal child advanced high-water")
	}
}

func TestSyncRefusesMutationCapableResultWhenHighWaterCannotPersist(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	_, err := Sync(objects, verifier, &highWaterFake{fail: true}, ceremonyID, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err=%v", err)
	}
}

func TestSyncRejectsRootForAnotherCeremony(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	rootRaw := objects[state.RootKey(ceremonyID)]
	var root state.Root
	if err := json.Unmarshal(rootRaw, &root); err != nil {
		t.Fatal(err)
	}
	root.CeremonyID = "sha256:" + strings.Repeat("2", 64)
	changed, _ := json.Marshal(root)
	objects[state.RootKey(ceremonyID)] = changed
	if _, err := Sync(objects, verifier, &highWaterFake{}, ceremonyID, t.TempDir()); err == nil {
		t.Fatal("cross-ceremony root accepted")
	}
}

func TestSyncRejectsCheckpointDigestMismatch(t *testing.T) {
	objects, verifier, ceremonyID := fixture(t)
	var root state.Root
	_ = json.Unmarshal(objects[state.RootKey(ceremonyID)], &root)
	objects[store.Key(root.Checkpoint.SHA256)] = []byte("different bytes")
	root.Checkpoint.Size = int64(len("different bytes"))
	rootRaw, _ := root.Encode()
	objects[state.RootKey(ceremonyID)] = rootRaw
	if _, err := Sync(objects, verifier, &highWaterFake{}, ceremonyID, t.TempDir()); err == nil {
		t.Fatal("wrong checkpoint bytes accepted")
	}
}
