package transcript

import (
	"errors"
	"fmt"
)

const (
	maxSubmissionRecordBytes    = 16 << 20
	maxSubmissionSignatureBytes = 4096
)

// Submission asks the approved proof-tool to authenticate an exact inbox
// submission against an exact signed checkpoint slot. The proof-tool performs
// bounded reads of the manifest, envelope, and signature.
func (i Inspector) Submission(paths SubmissionInspectionPaths) (SubmissionInspection, error) {
	result, err := i.execute(
		"inspect", "submission",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--checkpoint", paths.CheckpointPath,
		"--checkpoint-signature", paths.CheckpointSignaturePath,
		"--kind", paths.Kind,
		"--phase", paths.Phase,
		"--index", fmt.Sprint(paths.Index),
		"--submitter-id", paths.SubmitterID,
		"--attempt-id", paths.AttemptID,
		"--envelope", paths.EnvelopePath,
		"--envelope-signature", paths.EnvelopeSignaturePath,
		"--manifest", paths.ManifestPath,
	)
	if err != nil {
		return SubmissionInspection{}, err
	}
	if result.Command != "inspect submission" || result.SubmissionInspection == nil {
		return SubmissionInspection{}, errors.New("mpc-ceremony returned no submission inspection")
	}
	inspection := *result.SubmissionInspection
	if inspection.Schema != submissionInspectionSchema || inspection.CeremonyID == "" ||
		inspection.Workflow != "storage-first-v1" || inspection.RelayReleaseID == "" ||
		inspection.SubmitterID == "" || inspection.SubmitterKeyID == "" || inspection.SubmitterRole != "participant" ||
		(inspection.Kind != "receipt" && inspection.Kind != "candidate") || inspection.Phase != "phase1" ||
		inspection.Index == 0 || inspection.AttemptID == "" || inspection.ManifestKey == "" ||
		inspection.ParentCheckpointSHA256 == "" || inspection.AllocationCheckpointSHA256 == "" || inspection.ParentHeadID == "" {
		return SubmissionInspection{}, errors.New("mpc-ceremony returned an invalid submission inspection")
	}
	if len(inspection.Payloads) == 0 || len(inspection.Payloads) > 64 {
		return SubmissionInspection{}, errors.New("mpc-ceremony returned an invalid submission payload inventory")
	}
	for index, ref := range inspection.Payloads {
		if err := validateRef(ref); err != nil {
			return SubmissionInspection{}, fmt.Errorf("submission payload %d: %w", index, err)
		}
	}
	manifest := ArtifactRef{Name: inspection.ManifestKey, Digest: inspection.ManifestDigest}
	if err := validateRef(manifest); err != nil || manifest.Digest.Size <= 0 || manifest.Digest.Size > maxSubmissionRecordBytes {
		return SubmissionInspection{}, errors.New("mpc-ceremony returned an invalid submission manifest digest")
	}
	for label, bounded := range map[string]struct {
		digest Digest
		max    int64
	}{
		"envelope":           {inspection.EnvelopeDigest, maxSubmissionRecordBytes},
		"envelope signature": {inspection.EnvelopeSignatureDigest, maxSubmissionSignatureBytes},
	} {
		if err := validateRef(ArtifactRef{Name: "submission/" + label, Digest: bounded.digest}); err != nil ||
			bounded.digest.Size <= 0 || bounded.digest.Size > bounded.max {
			return SubmissionInspection{}, fmt.Errorf("mpc-ceremony returned an invalid %s digest", label)
		}
	}
	return inspection, nil
}
