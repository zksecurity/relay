package storagefirst

import (
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
)

// ProofToolVerifier adapts the approved mpc-ceremony inspection projection to
// the deliberately smaller storage synchronizer interface.
type ProofToolVerifier struct{ Inspector transcript.Inspector }

func (v ProofToolVerifier) VerifyCheckpoint(checkpointPath, signaturePath string) (Checkpoint, error) {
	inspection, err := v.Inspector.Checkpoint(checkpointPath, signaturePath)
	if err != nil {
		return Checkpoint{}, err
	}
	definition, err := v.Inspector.Definition()
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{
		CeremonyID: inspection.CeremonyID,
		Position: state.CheckpointPosition{
			Sequence: inspection.Sequence,
			Digest:   inspection.Digest.SHA256,
			PhaseHeads: map[string]state.PhaseHeadPosition{
				"phase1": {Index: uint64(inspection.Phase1.AcceptedCount), Digest: inspection.Phase1.HeadRecordID},
			},
		},
		Transition:           inspection.Transition.Kind,
		ParticipantID:        inspection.Transition.ParticipantID,
		Phase1Accepted:       int(inspection.Phase1.AcceptedCount),
		Phase1ScheduledTotal: len(definition.Phase1Participants),
	}
	checkpoint.Definition = SignedRef{Checkpoint: contentRef(inspection.Definition.Record), Signature: contentRef(inspection.Definition.Signature)}
	for _, artifact := range inspection.AcceptedArtifacts {
		checkpoint.Artifacts = append(checkpoint.Artifacts, contentRef(artifact))
	}
	checkpoint.Phase1Closed = checkpoint.Position.PhaseHeads["phase1"].Closed
	if !checkpoint.Phase1Closed && checkpoint.Phase1Accepted < checkpoint.Phase1ScheduledTotal {
		checkpoint.Phase1NextParticipantID = definition.Phase1Participants[checkpoint.Phase1Accepted]
	}
	if inspection.PreviousCheckpoint != nil {
		previous := SignedRef{
			Checkpoint: contentRef(inspection.PreviousCheckpoint.Record),
			Signature:  contentRef(inspection.PreviousCheckpoint.Signature),
		}
		checkpoint.Previous = &previous
		checkpoint.Position.PreviousDigest = previous.Checkpoint.SHA256
	}
	for _, slot := range inspection.Submissions {
		projected := Slot{
			Kind: slot.Kind, Phase: slot.Phase, Index: int(slot.Index), IdentityID: slot.IdentityID,
			AttemptID: slot.AttemptID, ManifestKey: slot.ManifestKey,
			BasisCheckpointDigest: slot.BasisCheckpointSHA256, ParentHeadID: slot.ParentHeadID, Status: slot.Status,
		}
		if slot.Acknowledgement != nil {
			projected.AcknowledgementDigest = slot.Acknowledgement.Record.Digest.SHA256
		}
		checkpoint.Slots = append(checkpoint.Slots, projected)
		if inspection.PreviousCheckpoint != nil && inspection.Transition.Kind == "phase1-candidate-accepted" && projected.Kind == "candidate" &&
			projected.Status == "accepted" && projected.Index == int(inspection.Transition.Index) &&
			projected.IdentityID == inspection.Transition.ParticipantID && projected.AttemptID == inspection.Transition.AttemptID {
			checkpoint.AcceptedCandidate = &AcceptedCandidate{
				OperationCheckpointDigest: inspection.PreviousCheckpoint.Record.Digest.SHA256,
				BasisCheckpointDigest:     projected.BasisCheckpointDigest, Index: projected.Index,
				IdentityID: projected.IdentityID, AttemptID: projected.AttemptID,
				CandidateDigest:       inspection.Phase1.HeadPayload.Digest.SHA256,
				AcceptedHeadID:        inspection.Phase1.HeadRecordID,
				AcknowledgementDigest: projected.AcknowledgementDigest,
			}
		}
	}
	return checkpoint, nil
}

func (v ProofToolVerifier) VerifyTransition(previousCheckpointPath, previousSignaturePath, nextCheckpointPath, nextSignaturePath string) error {
	_, err := v.Inspector.CheckpointTransition(previousCheckpointPath, previousSignaturePath, nextCheckpointPath, nextSignaturePath)
	return err
}

func (v ProofToolVerifier) VerifyEvidence(artifactRoot, checkpointPath, signaturePath string) (EvidenceVerification, error) {
	inspector := v.Inspector
	checkpoint, err := inspector.Checkpoint(checkpointPath, signaturePath)
	if err != nil {
		return EvidenceVerification{}, err
	}
	inspector.CeremonyPath = filepath.Join(artifactRoot, filepath.FromSlash(checkpoint.Definition.Record.Name))
	inspector.CeremonySignaturePath = filepath.Join(artifactRoot, filepath.FromSlash(checkpoint.Definition.Signature.Name))
	inspection, err := inspector.CheckpointEvidence(artifactRoot, checkpointPath, signaturePath)
	if err != nil {
		return EvidenceVerification{}, err
	}
	return EvidenceVerification{
		CeremonyID: inspection.CeremonyID, Sequence: inspection.Sequence,
		Digest: inspection.CheckpointDigest.SHA256, TransitionKind: inspection.TransitionKind,
		FullyVerified: inspection.FullyVerified,
	}, nil
}

func contentRef(ref transcript.ArtifactRef) state.ContentRef {
	return state.ContentRef{Name: ref.Name, SHA256: ref.Digest.SHA256, Size: ref.Digest.Size}
}
