package storagefirst

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type verifierV4Fake struct {
	discoveries        map[string]transcript.CheckpointDiscoveryV4
	full               transcript.CheckpointInspectionV4
	reject             bool
	fullCalls          int
	requiredDependency string
}

func (v *verifierV4Fake) DiscoverCheckpointV4(_, record, _ string) (transcript.CheckpointDiscoveryV4, error) {
	b, err := os.ReadFile(record)
	if err != nil {
		return transcript.CheckpointDiscoveryV4{}, err
	}
	d, ok := v.discoveries[sum(b)]
	if !ok {
		return d, errors.New("unknown checkpoint")
	}
	return d, nil
}
func (v *verifierV4Fake) StoredCheckpointV4(root, _, _ string) (transcript.CheckpointInspectionV4, error) {
	v.fullCalls++
	if v.requiredDependency != "" {
		if _, err := os.Stat(filepath.Join(root, v.requiredDependency)); err != nil {
			return transcript.CheckpointInspectionV4{}, err
		}
	}
	if v.reject {
		return transcript.CheckpointInspectionV4{}, errors.New("illegal signed ancestry")
	}
	return v.full, nil
}

type interruptedHighWaterV4 struct {
	HighWater
	writes int
	failAt int
}

func (h *interruptedHighWaterV4) Record(p state.CheckpointPosition) error {
	h.writes++
	if h.writes == h.failAt {
		return errors.New("interrupted persistence")
	}
	return h.HighWater.Record(p)
}

func TestSyncV4StagesDependenciesAndResumesPartialPersistence(t *testing.T) {
	objects, verifier, id := syncFixtureV4(t, 3)
	dependency := []byte("bounded governance record")
	objects[store.Key(sum(dependency))] = dependency
	d := verifier.discoveries[verifier.full.CheckpointRefs.Record.Digest.SHA256]
	d.Discovery.VerificationDependencies = []transcript.ArtifactRef{{Name: "governance/record.json", Digest: transcript.Digest{SHA256: sum(dependency), Size: int64(len(dependency))}}}
	verifier.discoveries[verifier.full.CheckpointRefs.Record.Digest.SHA256] = d
	verifier.requiredDependency = "governance/record.json"
	h, err := state.OpenWorkspaceHighWater(t.TempDir(), id)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := &interruptedHighWaterV4{HighWater: h, failAt: 3}
	if _, err := SyncV4(objects, verifier, interrupted, id, t.TempDir()); err == nil {
		t.Fatal("persistence failure hidden")
	}
	position, exists, err := h.Seen()
	if err != nil || !exists || position.Sequence != 1 {
		t.Fatalf("partial progress lost: %+v %v", position, err)
	}
	verifier.fullCalls = 0
	if _, err := SyncV4(objects, verifier, h, id, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	position, _, _ = h.Seen()
	if position.Sequence != 3 || verifier.fullCalls != 1 {
		t.Fatal("resume did not verify and finish")
	}
}

func syncFixtureV4(t *testing.T, last int) (memoryObjects, *verifierV4Fake, string) {
	t.Helper()
	id := sum([]byte("ceremony"))
	objects := memoryObjects{}
	v := &verifierV4Fake{discoveries: map[string]transcript.CheckpointDiscoveryV4{}}
	var previous *transcript.SignedArtifactRefs
	artifact := func(name string, raw []byte) transcript.ArtifactRef {
		objects[store.Key(sum(raw))] = raw
		return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: sum(raw), Blake2b256: "blake2b256:" + sum(raw)[7:], Size: int64(len(raw))}}
	}
	for n := 0; n <= last; n++ {
		pair := transcript.SignedArtifactRefs{Record: artifact(fmt.Sprintf("checkpoints/%d.json", n), []byte(fmt.Sprintf("checkpoint-%d", n))), Signature: artifact(fmt.Sprintf("checkpoints/%d.sig", n), []byte(fmt.Sprintf("signature-%d", n)))}
		d := transcript.CheckpointDiscoveryV4{Schema: "proof-tool-mpc-checkpoint-discovery-v4", Depth: "signed-checkpoint-discovery", CheckpointRefs: pair}
		d.Discovery.CeremonyID, d.Discovery.Sequence, d.Discovery.PreviousCheckpoint, d.Discovery.VerificationDependencies = id, uint64(n), previous, []transcript.ArtifactRef{}
		v.discoveries[pair.Record.Digest.SHA256] = d
		v.full = transcript.CheckpointInspectionV4{Schema: "proof-tool-mpc-checkpoint-inspection-v4", Depth: "checkpoint-structure", CheckpointRefs: pair, Checkpoint: transcript.CheckpointStateV4{Schema: "proof-tool-mpc-checkpoint-v4", Workflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", CeremonyID: id, Sequence: uint64(n), PreviousCheckpoint: previous, Deliveries: []transcript.DeliverySlotV4{}}}
		copy := pair
		previous = &copy
	}
	root := state.Root{Schema: state.RootSchema, CeremonyID: id, Checkpoint: contentRef(previous.Record), CheckpointSignature: contentRef(previous.Signature)}
	raw, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	objects[state.RootKey(id)] = raw
	return objects, v, id
}

func TestSyncV4VerifiesOnceBeforeRecordingAndResumes(t *testing.T) {
	objects, verifier, id := syncFixtureV4(t, 3)
	h, err := state.OpenWorkspaceHighWater(t.TempDir(), id)
	if err != nil {
		t.Fatal(err)
	}
	verifier.reject = true
	if _, err := SyncV4(objects, verifier, h, id, t.TempDir()); err == nil {
		t.Fatal("illegal ancestry accepted")
	}
	if _, exists, err := h.Seen(); err != nil || exists {
		t.Fatalf("failed verification changed progress: %v", err)
	}
	verifier.reject, verifier.fullCalls = false, 0
	snapshot, err := SyncV4(objects, verifier, h, id, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if verifier.fullCalls != 1 || snapshot.Checked() != 4 {
		t.Fatal("unexpected verification count")
	}
	current, err := snapshot.State()
	if err != nil {
		t.Fatal(err)
	}
	current.Deliveries = append(current.Deliveries, transcript.DeliverySlotV4{AttemptID: "forged"})
	unchanged, _ := snapshot.State()
	if len(unchanged.Deliveries) != 0 {
		t.Fatal("snapshot mutation escaped")
	}
	if _, err := SyncV4(objects, verifier, h, id, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := (SnapshotV4{}).State(); err == nil {
		t.Fatal("empty snapshot usable")
	}
}

func TestSyncV4RejectsIncompleteOrInconsistentDiscovery(t *testing.T) {
	for _, variant := range []string{"missing-signature", "missing-dependency", "conflicting-name", "oversized", "wrong-full-head", "wrong-full-policy", "wrong-full-ceremony", "wrong-full-signature", "wrong-predecessor-signature", "cycle", "sequence-limit", "wrong-sequence", "discovery-overclaim", "disk-full"} {
		t.Run(variant, func(t *testing.T) {
			objects, verifier, id := syncFixtureV4(t, 2)
			h := &highWaterFake{}
			last := verifier.full.CheckpointRefs
			d := verifier.discoveries[last.Record.Digest.SHA256]
			switch variant {
			case "missing-signature":
				delete(objects, store.Key(last.Signature.Digest.SHA256))
			case "missing-dependency":
				d.Discovery.VerificationDependencies = []transcript.ArtifactRef{{Name: "missing", Digest: last.Record.Digest}}
				d.Discovery.VerificationDependencies[0].Digest.SHA256 = sum([]byte("absent"))
			case "conflicting-name":
				d.Discovery.VerificationDependencies = []transcript.ArtifactRef{{Name: last.Record.Name, Digest: last.Signature.Digest}}
			case "oversized":
				d.Discovery.VerificationDependencies = []transcript.ArtifactRef{{Name: "too-big", Digest: last.Record.Digest}}
				d.Discovery.VerificationDependencies[0].Digest.Size = 16<<20 + 1
			case "wrong-full-head":
				verifier.full.Checkpoint.Sequence++
			case "wrong-full-policy":
				verifier.full.Checkpoint.ReleaseVerification = "skip"
			case "wrong-full-ceremony":
				verifier.full.Checkpoint.CeremonyID = sum([]byte("other ceremony"))
			case "wrong-full-signature":
				verifier.full.CheckpointRefs.Signature.Digest.SHA256 = sum([]byte("other signature"))
			case "wrong-predecessor-signature":
				changed := *verifier.full.Checkpoint.PreviousCheckpoint
				changed.Signature.Digest.SHA256 = sum([]byte("other signature"))
				verifier.full.Checkpoint.PreviousCheckpoint = &changed
			case "cycle":
				d.Discovery.PreviousCheckpoint = &last
			case "sequence-limit":
				d.Discovery.Sequence = transcript.MaxCheckpointSequenceV4 + 1
			case "wrong-sequence":
				d.Discovery.Sequence += 2
			case "discovery-overclaim":
				d.AncestryVerified = true
			case "disk-full":
				h.fail = true
			}
			verifier.discoveries[last.Record.Digest.SHA256] = d
			if _, err := SyncV4(objects, verifier, h, id, t.TempDir()); err == nil {
				t.Fatal("bad discovery accepted")
			}
			if h.exists {
				t.Fatal("failure advanced saved progress")
			}
		})
	}
}

func TestSyncV4SupportsHistoryBeyondLegacyLimit(t *testing.T) {
	for _, last := range []int{1025, transcript.MaxCheckpointSequenceV4} {
		objects, verifier, id := syncFixtureV4(t, last)
		s, err := SyncV4(objects, verifier, &highWaterFake{}, id, t.TempDir())
		if err != nil || s.Checked() != last+1 || verifier.fullCalls != 1 {
			t.Fatalf("%d %v", s.Checked(), err)
		}
	}
}

func TestSyncV4RejectsRollbackAndForkWithoutChangingSavedProgress(t *testing.T) {
	objects, verifier, id := syncFixtureV4(t, 2)
	h, err := state.OpenWorkspaceHighWater(t.TempDir(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SyncV4(objects, verifier, h, id, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	before, _, _ := h.Seen()
	oldObjects, oldVerifier, _ := syncFixtureV4(t, 1)
	if _, err := SyncV4(oldObjects, oldVerifier, h, id, t.TempDir()); err == nil {
		t.Fatal("rollback accepted")
	}
	// The correct sequence with a different signed history is not a resume.
	forkHighWater := &highWaterFake{exists: true, position: state.CheckpointPosition{Sequence: 2, Digest: sum([]byte("other history"))}}
	if _, err := SyncV4(objects, verifier, forkHighWater, id, t.TempDir()); err == nil {
		t.Fatal("fork accepted")
	}
	after, _, _ := h.Seen()
	if after.Sequence != before.Sequence || after.Digest != before.Digest {
		t.Fatal("rollback changed progress")
	}
}

func TestSyncV4DoesNotFetchLargeHistoricalPayloads(t *testing.T) {
	objects, verifier, id := syncFixtureV4(t, 1)
	verifier.full.Checkpoint.Progress.Phase1.HeadPayload = transcript.ArtifactRef{Name: "phase1/large.bin", Digest: transcript.Digest{SHA256: sum([]byte("not stored")), Size: 32 << 20}}
	if _, err := SyncV4(objects, verifier, &highWaterFake{}, id, t.TempDir()); err != nil {
		t.Fatalf("metadata sync required absent payload: %v", err)
	}
}
