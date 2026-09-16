package storagefirst

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// RootWriter is the authenticated coordinator-storage surface used for the
// single mutable discovery object.
type RootWriter interface {
	GetVersionedAtMost(key, localPath string, maximum int64) (store.ObjectVersion, error)
	PutIfAbsent(key, localPath string) (store.ObjectVersion, error)
	PutIfMatch(key, localPath string, expected store.ObjectVersion) (store.ObjectVersion, error)
}

// AuthenticatedRootChild is an opaque proof-tool-authenticated checkpoint and
// signature pair. Callers obtain it with AuthenticateRootChild; its unexported
// fields prevent CommitRoot from accepting bare caller assertions about a
// checkpoint's parent or authenticated bytes.
type AuthenticatedRootChild struct {
	checkpoint    Checkpoint
	checkpointRef state.ContentRef
	signatureRef  state.ContentRef
}

// PublicationVerifierV4 is the narrow proof-tool boundary used before a V4
// checkpoint can become the discoverable storage head. Its implementation
// must authenticate the signature and full ancestry and recheck the exact
// transition evidence, including mathematical replay for candidate acceptance.
type PublicationVerifierV4 interface {
	AuthenticateCheckpointForPublicationV4(root, record, signature string) (transcript.CheckpointInspectionV4, error)
}

// AuthenticateRootChildV4 adapts proof-tool's V4 projection to the existing
// provider-independent root commit primitive. No V4 checkpoint JSON is parsed
// by Relay to manufacture the authorization.
func AuthenticateRootChildV4(verifier PublicationVerifierV4, checkpointRef, signatureRef state.ContentRef, artifactRoot, checkpointPath, signaturePath string) (AuthenticatedRootChild, error) {
	if verifier == nil {
		return AuthenticatedRootChild{}, errors.New("V4 checkpoint verifier is required")
	}
	if err := verifyLocalRef(checkpointRef, checkpointPath); err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("checkpoint bytes: %w", err)
	}
	if err := verifyLocalRef(signatureRef, signaturePath); err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("checkpoint signature bytes: %w", err)
	}
	inspection, err := verifier.AuthenticateCheckpointForPublicationV4(artifactRoot, checkpointPath, signaturePath)
	if err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("authenticate V4 checkpoint for publication: %w", err)
	}
	c := inspection.Checkpoint
	if contentRef(inspection.CheckpointRefs.Record) != checkpointRef || contentRef(inspection.CheckpointRefs.Signature) != signatureRef {
		return AuthenticatedRootChild{}, errors.New("proof-tool V4 checkpoint references do not match the exact local bytes")
	}
	projected := Checkpoint{
		CeremonyID: c.CeremonyID,
		Position: state.CheckpointPosition{
			Sequence: c.Sequence,
			Digest:   checkpointRef.SHA256,
		},
		Transition: c.Transition.Kind,
	}
	if projected.Transition == "" {
		return AuthenticatedRootChild{}, errors.New("proof-tool V4 checkpoint projection has no transition kind")
	}
	if c.PreviousCheckpoint != nil {
		previous := SignedRef{Checkpoint: contentRef(c.PreviousCheckpoint.Record), Signature: contentRef(c.PreviousCheckpoint.Signature)}
		projected.Previous = &previous
		projected.Position.PreviousDigest = previous.Checkpoint.SHA256
	}
	return AuthenticatedRootChild{checkpoint: projected, checkpointRef: checkpointRef, signatureRef: signatureRef}, nil
}

// AuthenticateRootChild binds a proof-tool-authenticated checkpoint projection
// to the exact local checkpoint and signature bytes that will be published.
// Relay does not parse the signed checkpoint to manufacture this projection.
func AuthenticateRootChild(verifier Verifier, checkpointRef, signatureRef state.ContentRef, artifactRoot, checkpointPath, signaturePath string) (AuthenticatedRootChild, error) {
	if verifier == nil {
		return AuthenticatedRootChild{}, errors.New("checkpoint verifier is required")
	}
	if err := verifyLocalRef(checkpointRef, checkpointPath); err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("checkpoint bytes: %w", err)
	}
	if err := verifyLocalRef(signatureRef, signaturePath); err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("checkpoint signature bytes: %w", err)
	}
	checkpoint, err := verifier.VerifyCheckpoint(checkpointPath, signaturePath)
	if err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("authenticate checkpoint: %w", err)
	}
	if checkpoint.Position.Digest != checkpointRef.SHA256 {
		return AuthenticatedRootChild{}, errors.New("proof-tool checkpoint digest does not match the exact checkpoint bytes")
	}
	evidence, err := verifier.VerifyEvidence(artifactRoot, checkpointPath, signaturePath)
	if err != nil {
		return AuthenticatedRootChild{}, fmt.Errorf("fully verify checkpoint evidence: %w", err)
	}
	if !evidence.FullyVerified || evidence.CeremonyID != checkpoint.CeremonyID ||
		evidence.Sequence != checkpoint.Position.Sequence || evidence.Digest != checkpoint.Position.Digest ||
		evidence.TransitionKind != checkpoint.Transition {
		return AuthenticatedRootChild{}, errors.New("full evidence verification does not match the authenticated checkpoint")
	}
	return AuthenticatedRootChild{checkpoint: checkpoint, checkpointRef: checkpointRef, signatureRef: signatureRef}, nil
}

// RootCommit describes one authenticated child and the exact root/version it
// descends from. The immutable child bytes must already be uploaded before this
// call; changing root only makes those existing bytes discoverable.
type RootCommit struct {
	CeremonyID string
	Child      AuthenticatedRootChild
	// Previous is nil only for initialization. Later commits must carry the
	// exact root/version read before preparing and signing the child.
	Previous        *state.Root
	PreviousVersion *store.ObjectVersion
}

// RootCommitStatus is the result of rereading the mutable discovery root after
// an attempted conditional update. Only RootCommitConfirmed is safe to record
// as a completed publication.
type RootCommitStatus string

const (
	RootCommitConfirmed  RootCommitStatus = "confirmed"
	RootCommitStillPrior RootCommitStatus = "still-prior"
	RootCommitUnexpected RootCommitStatus = "unexpected"
)

var ErrRootCommitUnconfirmed = errors.New("root commit was not confirmed by an exact reread")

// CommitRoot conditionally installs one discovery root. A conflict is never
// retried with a new parent: the caller must synchronize and determine whether
// its exact checkpoint committed or a competing child won.
func CommitRoot(objects RootWriter, commit RootCommit, tempParent string) (store.ObjectVersion, error) {
	if objects == nil {
		return store.ObjectVersion{}, errors.New("root writer is required")
	}
	next := state.Root{
		Schema:              state.RootSchema,
		CeremonyID:          commit.CeremonyID,
		Checkpoint:          commit.Child.checkpointRef,
		CheckpointSignature: commit.Child.signatureRef,
	}
	raw, err := next.Encode()
	if err != nil {
		return store.ObjectVersion{}, err
	}
	if (commit.Previous == nil) != (commit.PreviousVersion == nil) {
		return store.ObjectVersion{}, errors.New("previous root and previous version must be supplied together")
	}
	if commit.Child.checkpoint.CeremonyID != commit.CeremonyID {
		return store.ObjectVersion{}, errors.New("authenticated child belongs to another ceremony")
	}
	if commit.Previous != nil {
		if err := commit.Previous.Validate(); err != nil {
			return store.ObjectVersion{}, fmt.Errorf("previous root: %w", err)
		}
		if commit.Previous.CeremonyID != commit.CeremonyID {
			return store.ObjectVersion{}, errors.New("previous root belongs to another ceremony")
		}
		if commit.Previous.Checkpoint.SHA256 == commit.Child.checkpointRef.SHA256 {
			return store.ObjectVersion{}, errors.New("new root must advance to a different checkpoint")
		}
		if commit.Child.checkpoint.Previous == nil ||
			commit.Child.checkpoint.Previous.Checkpoint != commit.Previous.Checkpoint ||
			commit.Child.checkpoint.Previous.Signature != commit.Previous.CheckpointSignature {
			return store.ObjectVersion{}, errors.New("authenticated child does not descend from the exact checkpoint and signature named by the previous root")
		}
		if commit.Child.checkpoint.Position.PreviousDigest != commit.Previous.Checkpoint.SHA256 {
			return store.ObjectVersion{}, errors.New("authenticated child position does not bind the previous root checkpoint digest")
		}
		if err := RootStillNames(objects, *commit.Previous, *commit.PreviousVersion, tempParent); err != nil {
			return store.ObjectVersion{}, fmt.Errorf("recheck previous root before commit: %w", err)
		}
	} else if commit.Child.checkpoint.Position.Sequence != 0 || commit.Child.checkpoint.Previous != nil {
		return store.ObjectVersion{}, errors.New("initial root requires an authenticated sequence-zero checkpoint with no predecessor")
	}
	temp, err := os.MkdirTemp(tempParent, "relay-root-commit-")
	if err != nil {
		return store.ObjectVersion{}, err
	}
	defer os.RemoveAll(temp)
	// Root publication is last. Refuse to make a child discoverable until both
	// immutable objects can be reread and matched byte-for-byte from storage.
	if err := fetchExact(objects, commit.Child.checkpointRef, filepath.Join(temp, "checkpoint.json")); err != nil {
		return store.ObjectVersion{}, fmt.Errorf("verify uploaded checkpoint: %w", err)
	}
	if err := fetchExact(objects, commit.Child.signatureRef, filepath.Join(temp, "checkpoint.sig")); err != nil {
		return store.ObjectVersion{}, fmt.Errorf("verify uploaded checkpoint signature: %w", err)
	}
	rootPath := filepath.Join(temp, "root.json")
	if err := os.WriteFile(rootPath, raw, 0o600); err != nil {
		return store.ObjectVersion{}, err
	}
	key := state.RootKey(commit.CeremonyID)
	var committed store.ObjectVersion
	if commit.Previous == nil {
		committed, err = objects.PutIfAbsent(key, rootPath)
	} else {
		committed, err = objects.PutIfMatch(key, rootPath, *commit.PreviousVersion)
	}
	if err != nil {
		return store.ObjectVersion{}, err
	}
	status, observed, err := ReconcileRootCommit(objects, commit, committed, tempParent)
	if err != nil {
		return store.ObjectVersion{}, fmt.Errorf("%w: %v", ErrRootCommitUnconfirmed, err)
	}
	if status != RootCommitConfirmed {
		return store.ObjectVersion{}, fmt.Errorf("%w: storage reread status %s", ErrRootCommitUnconfirmed, status)
	}
	return observed, nil
}

// ReconcileRootCommit classifies the exact root currently visible through the
// authenticated provider API. It is safe to call after a crash with the
// intended write version retained in the coordinator journal. A caller may
// proceed only for RootCommitConfirmed; StillPrior means the conditional write
// did not become visible, and Unexpected means some other root/version won.
func ReconcileRootCommit(objects RootWriter, commit RootCommit, intendedVersion store.ObjectVersion, tempParent string) (RootCommitStatus, store.ObjectVersion, error) {
	if objects == nil {
		return RootCommitUnexpected, store.ObjectVersion{}, errors.New("root writer is required")
	}
	next := state.Root{
		Schema: state.RootSchema, CeremonyID: commit.CeremonyID,
		Checkpoint: commit.Child.checkpointRef, CheckpointSignature: commit.Child.signatureRef,
	}
	if err := next.Validate(); err != nil {
		return RootCommitUnexpected, store.ObjectVersion{}, err
	}
	temp, err := os.MkdirTemp(tempParent, "relay-root-reconcile-")
	if err != nil {
		return RootCommitUnexpected, store.ObjectVersion{}, err
	}
	defer os.RemoveAll(temp)
	rootPath := filepath.Join(temp, "root.json")
	observedVersion, err := objects.GetVersionedAtMost(state.RootKey(commit.CeremonyID), rootPath, maxRootBytes)
	if err != nil {
		return RootCommitUnexpected, store.ObjectVersion{}, err
	}
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		return RootCommitUnexpected, store.ObjectVersion{}, err
	}
	observed, err := state.DecodeRoot(raw)
	if err != nil {
		return RootCommitUnexpected, observedVersion, nil
	}
	if observed == next && sameRootVersion(observedVersion, intendedVersion) {
		return RootCommitConfirmed, observedVersion, nil
	}
	if commit.Previous != nil && observed == *commit.Previous && commit.PreviousVersion != nil && sameRootVersion(observedVersion, *commit.PreviousVersion) {
		return RootCommitStillPrior, observedVersion, nil
	}
	return RootCommitUnexpected, observedVersion, nil
}

func sameRootVersion(observed, expected store.ObjectVersion) bool {
	return observed.ETag == expected.ETag && observed.Size == expected.Size &&
		(expected.VersionID == "" || observed.VersionID == expected.VersionID)
}

// RootStillNames returns nil only when a new pinned read yields the exact root
// and provider version used to authorize an operation. Call immediately before
// signing, granting, accepting, or publishing.
func RootStillNames(objects RootWriter, expected state.Root, expectedVersion store.ObjectVersion, tempParent string) error {
	if objects == nil {
		return errors.New("root reader is required")
	}
	temp, err := os.MkdirTemp(tempParent, "relay-root-recheck-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	path := filepath.Join(temp, "root.json")
	version, err := objects.GetVersionedAtMost(state.RootKey(expected.CeremonyID), path, maxRootBytes)
	if err != nil {
		return err
	}
	if version.ETag != expectedVersion.ETag || (expectedVersion.VersionID != "" && version.VersionID != expectedVersion.VersionID) {
		return store.ErrVersionConflict
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	actual, err := state.DecodeRoot(raw)
	if err != nil {
		return err
	}
	if actual != expected {
		return store.ErrVersionConflict
	}
	return nil
}
