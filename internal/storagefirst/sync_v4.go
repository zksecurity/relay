package storagefirst

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// VerifierV4 is implemented by the approved-tool Inspector, not by parsing
// downloaded checkpoint JSON in Relay. Discovery must not authorize actions.
type VerifierV4 interface {
	DiscoverCheckpointV4(root, record, signature string) (transcript.CheckpointDiscoveryV4, error)
	CheckpointGuidanceV4(root, record, signature string) (transcript.CheckpointInspectionV4, transcript.EnrollmentMetadataInspectionV4, error)
}

// SnapshotV4 exists only after complete signed structural ancestry and committed
// enrollment verification. It proves neither payload availability, contribution
// replay, complete enrollment collection nor production approval.
// Its immutable state cannot be edited through returned slice/pointer aliases.
type SnapshotV4 struct {
	root        state.Root
	version     store.ObjectVersion
	head        transcript.SignedArtifactRefs
	files       []state.ContentRef
	structural  []state.ContentRef
	inspection  []byte
	commitments []byte
	enrollments []byte
	checked     int
	history     []string
}

func (s SnapshotV4) Root() (state.Root, store.ObjectVersion) { return s.root, s.version }
func (s SnapshotV4) Head() transcript.SignedArtifactRefs     { return s.head }
func (s SnapshotV4) Files() []state.ContentRef               { return append([]state.ContentRef(nil), s.files...) }
func (s SnapshotV4) StructuralFiles() []state.ContentRef {
	return append([]state.ContentRef(nil), s.structural...)
}
func (s SnapshotV4) Checked() int { return s.checked }
func (s SnapshotV4) ContainsCheckpointDigest(digest string) bool {
	return slices.Contains(s.history, digest)
}
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

func (s SnapshotV4) Commitments() (transcript.CheckpointCommitmentsV4, error) {
	var c transcript.CheckpointCommitmentsV4
	if len(s.commitments) == 0 {
		return c, errors.New("no verified V4 commitments")
	}
	err := json.Unmarshal(s.commitments, &c)
	return c, err
}

// Enrollment signatures and exact head binding were checked, not disclosure
// contents, roster completeness, independent people or contribution mathematics.
func (s SnapshotV4) Enrollments() (transcript.EnrollmentMetadataV4, error) {
	var e transcript.EnrollmentMetadataV4
	if len(s.enrollments) == 0 {
		return e, errors.New("no verified V4 enrollment metadata")
	}
	err := json.Unmarshal(s.enrollments, &e)
	return e, err
}

// SyncV4 follows signed discovery references, stages the metadata needed for
// structure and enrollment guidance, and verifies the full ancestry once. Callers
// hold their workspace lock across sync and any subsequent mutation intent.
// Existing V1–V3 ceremonies continue using Sync and their original semantics.
func SyncV4(objects ObjectStore, verifier VerifierV4, highWater HighWater, ceremonyID, tempParent string) (SnapshotV4, error) {
	return syncV4(objects, verifier, highWater, ceremonyID, tempParent, "")
}

// SyncV4Retained authenticates the same complete history as SyncV4 and then
// retains every verified public artifact at its signed logical path. Existing
// identical files make retries harmless; a different file at the same path is
// a conflict. High-water advances only after retention succeeds.
func SyncV4Retained(objects ObjectStore, verifier VerifierV4, highWater HighWater, ceremonyID, tempParent, retainedRoot string) (SnapshotV4, error) {
	if !filepath.IsAbs(retainedRoot) || filepath.Clean(retainedRoot) != retainedRoot {
		return SnapshotV4{}, errors.New("retained V4 artifact root must be an absolute clean path")
	}
	return syncV4(objects, verifier, highWater, ceremonyID, tempParent, retainedRoot)
}

func syncV4(objects ObjectStore, verifier VerifierV4, highWater HighWater, ceremonyID, tempParent, retainedRoot string) (SnapshotV4, error) {
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
	enrollmentRefs := map[transcript.SignedArtifactRefs]bool{}
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
		if pair := d.Enrollment; pair != nil {
			if len(enrollmentRefs) >= 128 || enrollmentRefs[*pair] || pair.Record.Digest.Size > 16<<20 || pair.Signature.Digest.Size > 4096 {
				return SnapshotV4{}, errors.New("invalid enrollment discovery set")
			}
			enrollmentRefs[*pair] = true
			for _, ref := range []transcript.ArtifactRef{pair.Record, pair.Signature} {
				if _, err := fetchNamed(objects, stage, contentRef(ref), names); err != nil {
					return SnapshotV4{}, fmt.Errorf("fetch enrollment guidance record: %w", err)
				}
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
	verified, metadata, err := verifier.CheckpointGuidanceV4(stage, headPath, headSig)
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
	structural := make([]state.ContentRef, 0, len(names))
	for _, ref := range names {
		structural = append(structural, ref)
	}
	slices.SortFunc(structural, func(a, b state.ContentRef) int { return strings.Compare(a.Name, b.Name) })
	public, err := transcript.RequiredPublicArtifactsV4(verified)
	if err != nil {
		return SnapshotV4{}, fmt.Errorf("derive required public artifacts: %w", err)
	}
	for _, ref := range public {
		if _, err := fetchNamed(objects, stage, contentRef(ref), names); err != nil {
			return SnapshotV4{}, fmt.Errorf("fetch required public artifact %q: %w", ref.Name, err)
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return SnapshotV4{}, err
	}
	start := len(backwards) - 1
	if haveSeen {
		start = seenIndex - 1
	}
	if verified.Commitments.Enrollments == nil || len(verified.Commitments.Enrollments) > 128 || verified.Commitments.Turns == nil || len(verified.Commitments.Turns) > 40 {
		return SnapshotV4{}, errors.New("missing or oversized checkpoint commitments")
	}
	if len(verified.Commitments.Enrollments) != len(enrollmentRefs) {
		return SnapshotV4{}, errors.New("enrollment discovery differs from verified set")
	}
	for _, pair := range verified.Commitments.Enrollments {
		if !enrollmentRefs[pair] {
			return SnapshotV4{}, errors.New("verified enrollment was not discovered")
		}
	}
	e := metadata.Metadata
	if metadata.Schema != "proof-tool-mpc-enrollment-metadata-v4" || metadata.Depth != "committed-enrollment-signatures" || !metadata.EnrollmentSignaturesVerified || metadata.DisclosureContentsVerified || metadata.CompleteRosterVerified || metadata.GlobalFreshnessVerified || e.CeremonyID != ceremonyID || e.Checkpoint != verified.CheckpointRefs || e.Enrollments == nil || len(e.Enrollments) != len(verified.Commitments.Enrollments) {
		return SnapshotV4{}, errors.New("enrollment metadata differs from verified head or boundary")
	}
	for n, enrollment := range e.Enrollments {
		if enrollment.Refs != verified.Commitments.Enrollments[n] {
			return SnapshotV4{}, errors.New("enrollment metadata is not the exact committed set")
		}
	}
	commitments, err := json.Marshal(verified.Commitments)
	if err != nil {
		return SnapshotV4{}, err
	}
	enrollments, err := json.Marshal(e)
	if err != nil {
		return SnapshotV4{}, err
	}
	if retainedRoot != "" {
		if err := retainVerifiedV4Artifacts(stage, retainedRoot, names); err != nil {
			return SnapshotV4{}, fmt.Errorf("retain verified public ceremony files: %w", err)
		}
	}
	// One complete verification passed. A partial persistence failure is safe
	// to resume; incomplete metadata never advances this workspace's position.
	for n := start; n >= 0; n-- {
		if err := highWater.Record(backwards[n]); err != nil {
			return SnapshotV4{}, fmt.Errorf("save verified progress: %w", err)
		}
	}
	files := make([]state.ContentRef, 0, len(names))
	for _, ref := range names {
		files = append(files, ref)
	}
	slices.SortFunc(files, func(a, b state.ContentRef) int { return strings.Compare(a.Name, b.Name) })
	history := make([]string, 0, len(backwards))
	for _, position := range backwards {
		history = append(history, position.Digest)
	}
	return SnapshotV4{root: root, version: version, head: verified.CheckpointRefs, files: files, structural: structural, inspection: encoded, commitments: commitments, enrollments: enrollments, checked: len(backwards), history: history}, nil
}

func retainVerifiedV4Artifacts(stage, destination string, names fetchedNames) error {
	if len(names) == 0 {
		return errors.New("verified artifact set is empty")
	}
	if err := ensureRetainedDirectory(destination, destination, "."); err != nil {
		return err
	}
	logical := make([]string, 0, len(names))
	for name := range names {
		logical = append(logical, name)
	}
	slices.Sort(logical)
	for _, name := range logical {
		ref := names[name]
		relative := filepath.FromSlash(name)
		if err := ensureRetainedDirectory(destination, filepath.Dir(filepath.Join(destination, relative)), filepath.Dir(relative)); err != nil {
			return err
		}
		source := filepath.Join(stage, relative)
		target := filepath.Join(destination, relative)
		if _, err := os.Lstat(target); err == nil {
			if err := verifyLocalRef(ref, target); err != nil {
				return fmt.Errorf("existing %q differs from verified storage bytes", name)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		temp, err := os.CreateTemp(filepath.Dir(target), ".relay-v4-artifact-")
		if err != nil {
			return err
		}
		tempPath := temp.Name()
		ok := false
		defer func() {
			if !ok {
				_ = os.Remove(tempPath)
			}
		}()
		input, err := os.Open(source)
		if err != nil {
			temp.Close()
			return err
		}
		_, copyErr := io.Copy(temp, input)
		closeInputErr := input.Close()
		syncErr := temp.Sync()
		closeErr := temp.Close()
		if copyErr != nil || closeInputErr != nil || syncErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeInputErr, syncErr, closeErr)
		}
		if err := verifyLocalRef(ref, tempPath); err != nil {
			return err
		}
		if err := os.Link(tempPath, target); err != nil {
			if _, statErr := os.Lstat(target); statErr == nil {
				if verifyErr := verifyLocalRef(ref, target); verifyErr == nil {
					ok = true
					_ = os.Remove(tempPath)
					continue
				}
			}
			return err
		}
		if err := os.Remove(tempPath); err != nil {
			return err
		}
		ok = true
	}
	return nil
}

func ensureRetainedDirectory(root, target, relative string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("retained artifact directory must use absolute clean paths")
	}
	within, err := filepath.Rel(root, target)
	if err != nil || within == ".." || filepath.IsAbs(within) || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return fmt.Errorf("retained artifact directory %q escapes its root", relative)
	}
	current := root
	if info, err := os.Lstat(current); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(current, 0700); err != nil {
			return err
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("retained artifact root must be a real directory")
	}
	if within == "." {
		return nil
	}
	for _, component := range strings.Split(within, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("retained artifact parent %q is not a real directory", relative)
		}
	}
	return nil
}
