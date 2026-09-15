// Package storagefirst reconstructs authenticated ceremony progress from an
// untrusted object store. It deliberately knows nothing about Docker, grants,
// or CLI menus: callers receive verified public facts and combine them with
// their own private/local prerequisites.
package storagefirst

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

const (
	maxRootBytes         = 64 << 10
	maxCheckpointCount   = 1024
	maxAcceptedArtifacts = 8192
)

// SignedRef names one immutable checkpoint and its detached signature.
type SignedRef struct {
	Checkpoint state.ContentRef
	Signature  state.ContentRef
}

// Slot is a coordinator-preallocated submission location. The credential that
// permits writing it is private and may be renewed; this public attempt does
// not change when a credential expires.
type Slot struct {
	Kind                  string
	Phase                 string
	Index                 int
	IdentityID            string
	AttemptID             string
	ManifestKey           string
	BasisCheckpointDigest string
	ParentHeadID          string
	Status                string
	AcknowledgementDigest string
}

type AcceptedCandidate struct {
	OperationCheckpointDigest string
	BasisCheckpointDigest     string
	Index                     int
	IdentityID                string
	AttemptID                 string
	CandidateDigest           string
	AcceptedHeadID            string
	AcknowledgementDigest     string
}

// Checkpoint is the stable projection emitted by the trusted proof-tool after
// it authenticates a checkpoint. Relay must not derive these facts by parsing
// the signed JSON itself.
type Checkpoint struct {
	CeremonyID              string
	Position                state.CheckpointPosition
	Previous                *SignedRef
	Definition              SignedRef
	Transition              string
	ParticipantID           string
	Phase1Accepted          int
	Phase1ScheduledTotal    int
	Phase1Closed            bool
	Phase1NextParticipantID string
	Phase2Accepted          int
	Phase2ScheduledTotal    int
	Phase2Closed            bool
	Phase2NextParticipantID string
	FinalCandidateRecorded  bool
	FinalReleaseRecorded    bool
	AcceptedCandidate       *AcceptedCandidate
	Slots                   []Slot
	Artifacts               []state.ContentRef
	authenticatedEvidence   bool
}

// Verifier is normally backed by the approved mpc-ceremony binary.
type Verifier interface {
	VerifyCheckpoint(checkpointPath, signaturePath string) (Checkpoint, error)
	VerifyTransition(previousCheckpointPath, previousSignaturePath, nextCheckpointPath, nextSignaturePath string) error
	VerifyEvidence(artifactRoot, checkpointPath, signaturePath string) (EvidenceVerification, error)
}

type EvidenceVerification struct {
	CeremonyID     string
	Sequence       uint64
	Digest         string
	TransitionKind string
	FullyVerified  bool
}

// ObjectStore is the strict subset needed for synchronization. Implementations
// must pin a versioned root read and bound every download.
type ObjectStore interface {
	GetVersionedAtMost(key, localPath string, maximum int64) (store.ObjectVersion, error)
}

// HighWater is durable, workspace-local rollback/fork state.
type HighWater interface {
	Seen() (state.CheckpointPosition, bool, error)
	Check(state.CheckpointPosition) error
	Record(state.CheckpointPosition) error
}

type Snapshot struct {
	Root        state.Root
	RootVersion store.ObjectVersion
	Checkpoint  Checkpoint
	Checked     int
}

type verifiedFile struct {
	checkpointPath string
	signaturePath  string
	checkpoint     Checkpoint
}

type fetchedNames map[string]state.ContentRef

// Sync authenticates the root's checkpoint and every missing ancestor before
// it advances local high-water state. A failed high-water write means the
// caller receives no mutation-capable snapshot.
func Sync(objects ObjectStore, verifier Verifier, highWater HighWater, ceremonyID, tempParent string) (Snapshot, error) {
	if objects == nil || verifier == nil || highWater == nil {
		return Snapshot{}, errors.New("storage, verifier, and high-water store are required")
	}
	temp, err := os.MkdirTemp(tempParent, "relay-checkpoint-sync-")
	if err != nil {
		return Snapshot{}, err
	}
	defer os.RemoveAll(temp)

	rootPath := filepath.Join(temp, "root.json")
	rootVersion, err := objects.GetVersionedAtMost(state.RootKey(ceremonyID), rootPath, maxRootBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("fetch discovery root: %w", err)
	}
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		return Snapshot{}, err
	}
	root, err := state.DecodeRoot(raw)
	if err != nil {
		return Snapshot{}, err
	}
	if root.CeremonyID != ceremonyID {
		return Snapshot{}, errors.New("discovery root belongs to another ceremony")
	}

	seen, haveSeen, err := highWater.Seen()
	if err != nil {
		return Snapshot{}, fmt.Errorf("read checkpoint high-water: %w", err)
	}

	ref := SignedRef{Checkpoint: root.Checkpoint, Signature: root.CheckpointSignature}
	var backwards []verifiedFile
	names := make(fetchedNames)
	seenIndex := -1
	for len(backwards) < maxCheckpointCount {
		entry, err := fetchAndVerify(objects, verifier, temp, ref, names)
		if err != nil {
			return Snapshot{}, err
		}
		backwards = append(backwards, entry)
		if haveSeen && entry.checkpoint.Position.Digest == seen.Digest {
			if err := highWater.Check(entry.checkpoint.Position); err != nil {
				return Snapshot{}, err
			}
			seenIndex = len(backwards) - 1
		}
		if entry.checkpoint.Position.Sequence == 0 {
			if entry.checkpoint.Previous != nil {
				return Snapshot{}, errors.New("initial checkpoint unexpectedly names a predecessor")
			}
			break
		}
		if entry.checkpoint.Previous == nil {
			return Snapshot{}, errors.New("checkpoint ancestry is incomplete")
		}
		ref = *entry.checkpoint.Previous
	}
	if len(backwards) == maxCheckpointCount {
		return Snapshot{}, errors.New("checkpoint ancestry exceeds the synchronization limit")
	}
	oldest := backwards[len(backwards)-1]
	if haveSeen && seenIndex < 0 {
		return Snapshot{}, errors.New("published checkpoint does not descend from this workspace's authenticated high-water mark")
	}
	if !haveSeen && oldest.checkpoint.Position.Sequence != 0 {
		return Snapshot{}, errors.New("fresh workspace could not authenticate checkpoint ancestry back to initialization")
	}

	// The latest checkpoint carries the append-only inventory needed to
	// reconstruct every accepted cp0-cp3 edge. Download it under each signed
	// logical name, then let proof-tool re-derive the complete ancestry before
	// changing durable local trust state.
	latestFile := backwards[0]
	if len(latestFile.checkpoint.Artifacts) == 0 || len(latestFile.checkpoint.Artifacts) > maxAcceptedArtifacts {
		return Snapshot{}, errors.New("checkpoint accepted-artifact inventory is empty or exceeds the synchronization limit")
	}
	for _, artifact := range latestFile.checkpoint.Artifacts {
		if _, err := fetchNamed(objects, temp, artifact, names); err != nil {
			return Snapshot{}, fmt.Errorf("fetch accepted checkpoint evidence %q: %w", artifact.Name, err)
		}
	}

	// Structural edge validation gives focused diagnostics. Full evidence
	// verification below is the authority for advancing the high-water mark.
	for index := len(backwards) - 1; index >= 0; index-- {
		current := backwards[index]
		if index < len(backwards)-1 {
			previous := backwards[index+1]
			if err := verifier.VerifyTransition(previous.checkpointPath, previous.signaturePath, current.checkpointPath, current.signaturePath); err != nil {
				return Snapshot{}, fmt.Errorf("verify checkpoint transition: %w", err)
			}
		}
	}
	evidence, err := verifier.VerifyEvidence(temp, latestFile.checkpointPath, latestFile.signaturePath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("fully verify checkpoint evidence: %w", err)
	}
	if !evidence.FullyVerified || evidence.CeremonyID != ceremonyID ||
		evidence.Sequence != latestFile.checkpoint.Position.Sequence || evidence.Digest != latestFile.checkpoint.Position.Digest ||
		evidence.TransitionKind != latestFile.checkpoint.Transition {
		return Snapshot{}, errors.New("full evidence verification does not match the discovered checkpoint")
	}

	// A fresh workspace records cp0..latest. A returning workspace records only
	// the children after its already-authenticated checkpoint.
	start := len(backwards) - 1
	if haveSeen {
		start = seenIndex - 1
	}
	for index := start; index >= 0; index-- {
		if err := highWater.Record(backwards[index].checkpoint.Position); err != nil {
			return Snapshot{}, fmt.Errorf("persist checkpoint high-water: %w", err)
		}
	}

	latest := latestFile.checkpoint
	latest.authenticatedEvidence = true
	return Snapshot{Root: root, RootVersion: rootVersion, Checkpoint: latest, Checked: len(backwards)}, nil
}

func fetchAndVerify(objects ObjectStore, verifier Verifier, temp string, ref SignedRef, names fetchedNames) (verifiedFile, error) {
	checkpointPath, err := fetchNamed(objects, temp, ref.Checkpoint, names)
	if err != nil {
		return verifiedFile{}, fmt.Errorf("fetch checkpoint: %w", err)
	}
	signaturePath, err := fetchNamed(objects, temp, ref.Signature, names)
	if err != nil {
		return verifiedFile{}, fmt.Errorf("fetch checkpoint signature: %w", err)
	}
	checkpoint, err := verifier.VerifyCheckpoint(checkpointPath, signaturePath)
	if err != nil {
		return verifiedFile{}, fmt.Errorf("authenticate checkpoint: %w", err)
	}
	if checkpoint.Position.Digest != ref.Checkpoint.SHA256 {
		return verifiedFile{}, errors.New("proof-tool checkpoint digest does not match the fetched reference")
	}
	return verifiedFile{checkpointPath: checkpointPath, signaturePath: signaturePath, checkpoint: checkpoint}, nil
}

func fetchNamed(objects ObjectStore, root string, ref state.ContentRef, names fetchedNames) (string, error) {
	localName := filepath.FromSlash(ref.Name)
	if ref.Name == "" || filepath.IsAbs(localName) || filepath.Clean(localName) != localName ||
		localName == "." || localName == ".." || strings.HasPrefix(ref.Name, "../") || strings.Contains(ref.Name, `\`) {
		return "", errors.New("immutable reference has an unsafe logical name")
	}
	if previous, exists := names[ref.Name]; exists {
		if previous.SHA256 != ref.SHA256 || previous.Size != ref.Size {
			return "", errors.New("one logical artifact name refers to different immutable bytes")
		}
		return filepath.Join(root, localName), nil
	}
	localPath := filepath.Join(root, localName)
	if err := fetchExact(objects, ref, localPath); err != nil {
		return "", err
	}
	names[ref.Name] = ref
	return localPath, nil
}

func fetchExact(objects ObjectStore, ref state.ContentRef, localPath string) error {
	if ref.Size <= 0 {
		return errors.New("immutable reference has no positive size")
	}
	version, err := objects.GetVersionedAtMost(store.Key(ref.SHA256), localPath, ref.Size)
	if err != nil {
		return err
	}
	if version.Size != ref.Size {
		return fmt.Errorf("downloaded size %d, want %d", version.Size, ref.Size)
	}
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref.SHA256 {
		_ = os.Remove(localPath)
		return errors.New("downloaded object digest does not match its immutable reference")
	}
	return nil
}
