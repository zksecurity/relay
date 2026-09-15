package storagefirst

import (
	"errors"

	"github.com/zksecurity/relay/internal/transcript"
)

type SubmissionInspectionFiles struct {
	CheckpointPath          string
	CheckpointSignaturePath string
	EnvelopePath            string
	EnvelopeSignaturePath   string
	ManifestPath            string
}

// AuthenticateObservedSubmission returns an opaque readiness fact only after
// the approved proof-tool authenticates the exact allocated submission. A
// storage LIST or HEAD result is intentionally insufficient.
func AuthenticateObservedSubmission(verifier ProofToolVerifier, checkpoint Checkpoint, slot Slot, files SubmissionInspectionFiles) (AuthenticatedObservedSubmission, error) {
	if !checkpoint.authenticatedEvidence {
		return AuthenticatedObservedSubmission{}, errors.New("submission authentication requires a fully evidence-verified checkpoint")
	}
	found := false
	for _, candidate := range checkpoint.Slots {
		if candidate == slot {
			found = true
			break
		}
	}
	if !found || slot.Status != "allocated" {
		return AuthenticatedObservedSubmission{}, errors.New("submission does not target an exact allocated checkpoint slot")
	}
	inspection, err := verifier.Inspector.Submission(transcript.SubmissionInspectionPaths{
		CheckpointPath: files.CheckpointPath, CheckpointSignaturePath: files.CheckpointSignaturePath,
		Kind: slot.Kind, Phase: slot.Phase, Index: uint8(slot.Index), SubmitterID: slot.IdentityID,
		AttemptID: slot.AttemptID, EnvelopePath: files.EnvelopePath,
		EnvelopeSignaturePath: files.EnvelopeSignaturePath, ManifestPath: files.ManifestPath,
	})
	if err != nil {
		return AuthenticatedObservedSubmission{}, err
	}
	if inspection.CeremonyID != checkpoint.CeremonyID || inspection.Workflow != "storage-first-v1" ||
		inspection.Kind != slot.Kind || inspection.Phase != slot.Phase || int(inspection.Index) != slot.Index ||
		inspection.SubmitterID != slot.IdentityID || inspection.AttemptID != slot.AttemptID ||
		inspection.ManifestKey != slot.ManifestKey || inspection.ParentCheckpointSHA256 != slot.BasisCheckpointDigest ||
		inspection.AllocationCheckpointSHA256 != checkpoint.Position.Digest || inspection.ParentHeadID != slot.ParentHeadID ||
		!validDigest(inspection.ManifestDigest.SHA256) {
		return AuthenticatedObservedSubmission{}, errors.New("authenticated submission projection does not match the exact checkpoint slot")
	}
	return AuthenticatedObservedSubmission{
		ceremonyID: checkpoint.CeremonyID, checkpointDigest: checkpoint.Position.Digest,
		slot: slot, manifestDigest: inspection.ManifestDigest.SHA256,
	}, nil
}
