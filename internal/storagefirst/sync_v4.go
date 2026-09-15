package storagefirst

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// VerifierV4 is implemented by the approved-tool Inspector, not by parsing
// downloaded checkpoint JSON in Relay. Discovery must not authorize actions.
type VerifierV4 interface {
	DiscoverCheckpointV4(root, record, signature string) (transcript.CheckpointDiscoveryV4, error)
	StoredCheckpointV4(root, record, signature string) (transcript.CheckpointInspectionV4, error)
}

// SnapshotV4 exists only after complete signed structural ancestry verification. It proves
// neither payload availability, contribution replay nor production approval.
// Its immutable state cannot be edited through returned slice/pointer aliases.
type SnapshotV4 struct {
	root       state.Root
	version    store.ObjectVersion
	inspection []byte
	checked    int
}

func (s SnapshotV4) Root() (state.Root, store.ObjectVersion) { return s.root, s.version }
func (s SnapshotV4) Checked() int                            { return s.checked }
func (s SnapshotV4) State() (transcript.CheckpointStateV4, error) {
	if len(s.inspection) == 0 {
		return transcript.CheckpointStateV4{}, errors.New("no verified V4 snapshot")
	}
	var c transcript.CheckpointStateV4
	if err := json.Unmarshal(s.inspection, &c); err != nil {
		return c, err
	}
	return c, nil
}

// SyncV4 follows signed discovery references, stages only the metadata needed
// by stored verification, and calls the full ancestry verifier once. Callers
// hold their workspace lock across sync and any subsequent mutation intent.
// Existing V1–V3 ceremonies continue using Sync and their original semantics.
func SyncV4(objects ObjectStore, verifier VerifierV4, highWater HighWater, ceremonyID, tempParent string) (SnapshotV4, error) {
	if objects == nil || verifier == nil || highWater == nil || !validDigest(ceremonyID) {
		return SnapshotV4{}, errors.New("storage, V4 verifier, high-water and ceremony identity are required")
	}
	temp, err := os.MkdirTemp(tempParent, "relay-v4-sync-")
	if err != nil {
		return SnapshotV4{}, err
	}
	defer os.RemoveAll(temp)
	stage := filepath.Join(temp, "artifacts")
	if err := os.Mkdir(stage, 0700); err != nil {
		return SnapshotV4{}, err
	}
	rootPath := filepath.Join(temp, "discovery.json")
	version, err := objects.GetVersionedAtMost(state.RootKey(ceremonyID), rootPath, maxRootBytes)
	if err != nil {
		return SnapshotV4{}, fmt.Errorf("read ceremony progress: %w", err)
	}
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		return SnapshotV4{}, err
	}
	root, err := state.DecodeRoot(raw)
	if err != nil {
		return SnapshotV4{}, err
	}
	if root.CeremonyID != ceremonyID {
		return SnapshotV4{}, errors.New("progress belongs to another ceremony")
	}
	seen, haveSeen, err := highWater.Seen()
	if err != nil {
		return SnapshotV4{}, err
	}
	refs := SignedRef{Checkpoint: root.Checkpoint, Signature: root.CheckpointSignature}
	names := fetchedNames{}
	visited := map[string]bool{}
	var backwards []state.CheckpointPosition
	seenIndex := -1
	var headPath, headSig string
	var discoveredPrevious *transcript.SignedArtifactRefs
	for {
		if len(backwards) >= transcript.MaxCheckpointSequenceV4+1 {
			return SnapshotV4{}, errors.New("checkpoint history exceeds V4 protocol limit")
		}
		if refs.Checkpoint.Size > 16<<20 || refs.Signature.Size > 4096 {
			return SnapshotV4{}, errors.New("checkpoint pair exceeds verification size limit")
		}
		if visited[refs.Checkpoint.SHA256] {
			return SnapshotV4{}, errors.New("checkpoint history contains a cycle")
		}
		visited[refs.Checkpoint.SHA256] = true
		record, err := fetchNamed(objects, stage, refs.Checkpoint, names)
		if err != nil {
			return SnapshotV4{}, err
		}
		signature, err := fetchNamed(objects, stage, refs.Signature, names)
		if err != nil {
			return SnapshotV4{}, err
		}
		discovery, err := verifier.DiscoverCheckpointV4(stage, record, signature)
		if err != nil {
			return SnapshotV4{}, fmt.Errorf("discover signed history: %w", err)
		}
		d := discovery.Discovery
		if discovery.Schema != "proof-tool-mpc-checkpoint-discovery-v4" || discovery.Depth != "signed-checkpoint-discovery" || d.CeremonyID != ceremonyID || d.Sequence > transcript.MaxCheckpointSequenceV4 || discovery.AncestryVerified || discovery.ArtifactsVerified || discovery.MathematicsReplayed || discovery.GlobalFreshnessVerified || contentRef(discovery.CheckpointRefs.Record) != refs.Checkpoint || contentRef(discovery.CheckpointRefs.Signature) != refs.Signature {
			return SnapshotV4{}, errors.New("discovery does not match the exact fetched checkpoint")
		}
		if len(backwards) == 0 {
			headPath, headSig = record, signature
			discoveredPrevious = d.PreviousCheckpoint
		} else if d.Sequence+1 != backwards[len(backwards)-1].Sequence {
			return SnapshotV4{}, errors.New("checkpoint history skips a sequence")
		}
		p := state.CheckpointPosition{Sequence: d.Sequence, Digest: refs.Checkpoint.SHA256}
		if d.PreviousCheckpoint != nil {
			p.PreviousDigest = d.PreviousCheckpoint.Record.Digest.SHA256
		}
		backwards = append(backwards, p)
		if haveSeen && p.Digest == seen.Digest {
			if err := highWater.Check(p); err != nil {
				return SnapshotV4{}, err
			}
			seenIndex = len(backwards) - 1
		}
		if d.VerificationDependencies == nil || len(d.VerificationDependencies) > 5 {
			return SnapshotV4{}, errors.New("invalid V4 discovery dependencies")
		}
		for _, dependency := range d.VerificationDependencies {
			if dependency.Digest.Size > 16<<20 {
				return SnapshotV4{}, errors.New("discovery dependency exceeds metadata limit")
			}
			if _, err := fetchNamed(objects, stage, contentRef(dependency), names); err != nil {
				return SnapshotV4{}, fmt.Errorf("fetch history verification record: %w", err)
			}
		}
		if d.Sequence == 0 {
			if d.PreviousCheckpoint != nil {
				return SnapshotV4{}, errors.New("initial checkpoint names an ancestor")
			}
			break
		}
		if d.PreviousCheckpoint == nil {
			return SnapshotV4{}, errors.New("incomplete checkpoint history")
		}
		refs = SignedRef{Checkpoint: contentRef(d.PreviousCheckpoint.Record), Signature: contentRef(d.PreviousCheckpoint.Signature)}
	}
	if haveSeen && seenIndex < 0 {
		return SnapshotV4{}, errors.New("progress does not descend from this workspace's verified history")
	}
	verified, err := verifier.StoredCheckpointV4(stage, headPath, headSig)
	if err != nil {
		return SnapshotV4{}, fmt.Errorf("verify complete ceremony history: %w", err)
	}
	c := verified.Checkpoint
	if c.Schema != "proof-tool-mpc-checkpoint-v4" || c.Workflow != "storage-first-v2" || c.ReleaseVerification != "coordinator-full-replay-v1" {
		return SnapshotV4{}, errors.New("verified history has an incompatible protocol")
	}
	if (c.PreviousCheckpoint == nil) != (discoveredPrevious == nil) || (c.PreviousCheckpoint != nil && *c.PreviousCheckpoint != *discoveredPrevious) {
		return SnapshotV4{}, errors.New("verified predecessor differs from discovery")
	}
	if verified.Schema != "proof-tool-mpc-checkpoint-inspection-v4" || verified.Depth != "checkpoint-structure" || verified.ArtifactsVerified || verified.MathematicsReplayed || verified.GlobalFreshnessVerified || c.CeremonyID != ceremonyID || c.Sequence != backwards[0].Sequence || contentRef(verified.CheckpointRefs.Record) != root.Checkpoint || contentRef(verified.CheckpointRefs.Signature) != root.CheckpointSignature {
		return SnapshotV4{}, errors.New("verified history differs from discovered head")
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return SnapshotV4{}, err
	}
	start := len(backwards) - 1
	if haveSeen {
		start = seenIndex - 1
	}
	// All entries have now passed the one full ancestry check. A persistence
	// failure returns no snapshot; retained earlier positions are safe to resume.
	for n := start; n >= 0; n-- {
		if err := highWater.Record(backwards[n]); err != nil {
			return SnapshotV4{}, fmt.Errorf("save verified progress: %w", err)
		}
	}
	return SnapshotV4{root: root, version: version, inspection: encoded, checked: len(backwards)}, nil
}
