package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	commandResultSchema         = "proof-tool-mpc-command-result-v1"
	definitionInspectionSchema  = "proof-tool-mpc-definition-inspection-v1"
	chainInspectionSchema       = "proof-tool-mpc-chain-inspection-v1"
	participantInspectionSchema = "proof-tool-mpc-participant-inspection-v1"
	enrollmentInspectionSchema  = "proof-tool-mpc-enrollment-inspection-v1"
	submissionInspectionSchema  = "proof-tool-mpc-submission-inspection-v1"
)

// InspectionRunner invokes the trusted ceremony tool. It is exported so Relay
// can place participant-side inspections inside the same pinned Docker image
// used for the contribution.
type InspectionRunner func(executable string, args ...string) (stdout, stderr []byte, err error)

// Retained for package-local tests and callers compiled against the original
// unexported seam.
type inspectionRunner = InspectionRunner

// Inspector delegates ceremony document authentication and interpretation to
// the trusted mpc-ceremony binary. Relay consumes only its versioned projection.
type Inspector struct {
	Executable               string
	CeremonyPath             string
	CeremonySignaturePath    string
	CoordinatorPublicKeyPath string
	TranscriptRoot           string
	Runner                   InspectionRunner
	run                      inspectionRunner
}

type inspectionResult struct {
	Schema                         string                          `json:"schema"`
	OK                             bool                            `json:"ok"`
	Command                        string                          `json:"command"`
	DefinitionInspection           *Definition                     `json:"definition_inspection"`
	ChainInspection                *chainInspection                `json:"chain_inspection"`
	ParticipantInspection          *ParticipantInspection          `json:"participant_inspection"`
	EnrollmentInspection           *EnrollmentInspection           `json:"enrollment_inspection"`
	JourneyInspection              *Journey                        `json:"journey_inspection"`
	CheckpointInspection           *CheckpointInspection           `json:"checkpoint_inspection"`
	CheckpointTransitionInspection *CheckpointTransitionInspection `json:"checkpoint_transition_inspection"`
	CheckpointEvidenceInspection   *CheckpointEvidenceInspection   `json:"checkpoint_evidence_inspection"`
	SubmissionInspection           *SubmissionInspection           `json:"submission_inspection"`
	Error                          inspectionCommandError          `json:"error"`
}

// SignedArtifactRefs is the transport projection of a canonical record and
// its detached signature.
type SignedArtifactRefs struct {
	Record    ArtifactRef `json:"record"`
	Signature ArtifactRef `json:"signature"`
}

type CheckpointTransition struct {
	Kind          string `json:"kind"`
	Phase         string `json:"phase"`
	Index         uint8  `json:"index"`
	ParticipantID string `json:"participant_id"`
	AttemptID     string `json:"attempt_id"`
	NextAttemptID string `json:"next_attempt_id"`
}

type CheckpointPhaseState struct {
	Phase         string             `json:"phase"`
	AcceptedCount uint8              `json:"accepted_count"`
	HeadRecordID  string             `json:"head_record_id"`
	HeadPayload   ArtifactRef        `json:"head_payload"`
	Chain         SignedArtifactRefs `json:"chain"`
}

type CheckpointSubmissionSlot struct {
	Kind                  string              `json:"kind"`
	Phase                 string              `json:"phase"`
	Index                 uint8               `json:"index"`
	IdentityID            string              `json:"identity_id"`
	AttemptID             string              `json:"attempt_id"`
	ManifestKey           string              `json:"manifest_key"`
	BasisCheckpointSHA256 string              `json:"basis_checkpoint_sha256"`
	ParentHeadID          string              `json:"parent_head_id"`
	Status                string              `json:"status"`
	Acknowledgement       *SignedArtifactRefs `json:"acknowledgement"`
}

type CheckpointInspection struct {
	Schema             string                     `json:"schema"`
	CeremonyID         string                     `json:"ceremony_id"`
	Workflow           string                     `json:"workflow"`
	RelayReleaseID     string                     `json:"relay_release_id"`
	Sequence           uint64                     `json:"sequence"`
	Digest             Digest                     `json:"digest"`
	Definition         SignedArtifactRefs         `json:"definition"`
	PreviousCheckpoint *SignedArtifactRefs        `json:"previous_checkpoint"`
	Transition         CheckpointTransition       `json:"transition"`
	Phase1             CheckpointPhaseState       `json:"phase1"`
	Submissions        []CheckpointSubmissionSlot `json:"submissions"`
	AcceptedArtifacts  []ArtifactRef              `json:"accepted_artifacts"`
}

type CheckpointTransitionInspection struct {
	Schema                   string               `json:"schema"`
	CeremonyID               string               `json:"ceremony_id"`
	PreviousSequence         uint64               `json:"previous_sequence"`
	Sequence                 uint64               `json:"sequence"`
	PreviousCheckpointDigest Digest               `json:"previous_checkpoint_digest"`
	PreviousSignatureDigest  Digest               `json:"previous_signature_digest"`
	CheckpointDigest         Digest               `json:"checkpoint_digest"`
	Transition               CheckpointTransition `json:"transition"`
	Checkpoint               CheckpointInspection `json:"checkpoint"`
}

// CheckpointEvidenceInspection is emitted only after proof-tool has
// reconstructed the checkpoint from all of its stored evidence. Structural
// checkpoint inspection deliberately does not set this result.
type CheckpointEvidenceInspection struct {
	Schema                   string `json:"schema"`
	CeremonyID               string `json:"ceremony_id"`
	Sequence                 uint64 `json:"sequence"`
	CheckpointDigest         Digest `json:"checkpoint_digest"`
	TransitionKind           string `json:"transition_kind"`
	FullyVerified            bool   `json:"fully_verified"`
	VerifiedEvidenceBoundary string `json:"verified_evidence_boundary"`
}

// SubmissionInspection is emitted only after proof-tool authenticates the
// participant envelope and binds it to the exact allocated checkpoint slot and
// transport manifest bytes supplied by the caller.
type SubmissionInspection struct {
	Schema                     string        `json:"schema"`
	CeremonyID                 string        `json:"ceremony_id"`
	Workflow                   string        `json:"workflow"`
	RelayReleaseID             string        `json:"relay_release_id"`
	SubmitterID                string        `json:"submitter_id"`
	SubmitterKeyID             string        `json:"submitter_key_id"`
	SubmitterRole              string        `json:"submitter_role"`
	Kind                       string        `json:"kind"`
	Phase                      string        `json:"phase"`
	Index                      uint8         `json:"index"`
	ParentCheckpointSHA256     string        `json:"parent_checkpoint_sha256"`
	AllocationCheckpointSHA256 string        `json:"allocation_checkpoint_sha256"`
	ParentHeadID               string        `json:"parent_head_id"`
	AttemptID                  string        `json:"attempt_id"`
	ManifestKey                string        `json:"manifest_key"`
	Payloads                   []ArtifactRef `json:"payloads"`
	EnvelopeDigest             Digest        `json:"envelope_digest"`
	EnvelopeSignatureDigest    Digest        `json:"envelope_signature_digest"`
	ManifestDigest             Digest        `json:"manifest_digest"`
}

type SubmissionInspectionPaths struct {
	CheckpointPath          string
	CheckpointSignaturePath string
	Kind                    string
	Phase                   string
	Index                   uint8
	SubmitterID             string
	AttemptID               string
	EnvelopePath            string
	EnvelopeSignaturePath   string
	ManifestPath            string
}

type PublicIdentity struct {
	ID                   string `json:"id"`
	DisplayName          string `json:"display_name"`
	KeyID                string `json:"key_id"`
	Ed25519PublicKeyHex  string `json:"ed25519_public_key_hex"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type ParticipantInspection struct {
	Schema               string `json:"schema"`
	CeremonyID           string `json:"ceremony_id"`
	ParticipantID        string `json:"participant_id"`
	KeyID                string `json:"key_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Phase1Position       *uint8 `json:"phase1_position"`
	Phase2Position       *uint8 `json:"phase2_position"`
}

type EnrollmentInspection struct {
	Schema                 string         `json:"schema"`
	CeremonyID             string         `json:"ceremony_id"`
	Identity               PublicIdentity `json:"identity"`
	Role                   string         `json:"role"`
	RoleIndex              int            `json:"role_index"`
	IndependenceDisclosure ArtifactRef    `json:"independence_disclosure"`
	EnrolledAt             string         `json:"enrolled_at"`
}

type chainInspection struct {
	Schema        string        `json:"schema"`
	CeremonyID    string        `json:"ceremony_id"`
	Phase         string        `json:"phase"`
	AcceptedCount int           `json:"accepted_count"`
	Artifacts     []ArtifactRef `json:"artifacts"`
	Records       []ChainRecord `json:"records"`
}

type inspectionCommandError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (i Inspector) Definition() (Definition, error) {
	result, err := i.execute(
		"inspect", "definition",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
	)
	if err != nil {
		return Definition{}, err
	}
	if result.Command != "inspect definition" || result.DefinitionInspection == nil {
		return Definition{}, errors.New("mpc-ceremony returned no definition inspection")
	}
	definition := *result.DefinitionInspection
	if definition.Schema != definitionInspectionSchema {
		return Definition{}, fmt.Errorf("definition inspection schema %q, want %q", definition.Schema, definitionInspectionSchema)
	}
	if definition.CeremonyID == "" || definition.Mode == "" {
		return Definition{}, errors.New("definition inspection is missing ceremony identity or mode")
	}
	if len(definition.Phase1Participants) == 0 || len(definition.Phase2Participants) == 0 {
		return Definition{}, errors.New("definition inspection contains an empty participant schedule")
	}
	if err := validateRef(definition.R1CSRef); err != nil {
		return Definition{}, fmt.Errorf("definition inspection r1cs: %w", err)
	}
	return definition, nil
}

func (i Inspector) Chain(chainPath, chainSignaturePath string) (Chain, error) {
	result, err := i.execute(
		"inspect", "chain",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--transcript-root", i.TranscriptRoot,
		"--chain", chainPath,
		"--chain-signature", chainSignaturePath,
	)
	if err != nil {
		return Chain{}, err
	}
	if result.Command != "inspect chain" || result.ChainInspection == nil {
		return Chain{}, errors.New("mpc-ceremony returned no chain inspection")
	}
	inspection := result.ChainInspection
	if inspection.Schema != chainInspectionSchema {
		return Chain{}, fmt.Errorf("chain inspection schema %q, want %q", inspection.Schema, chainInspectionSchema)
	}
	if inspection.CeremonyID == "" || (inspection.Phase != "phase1" && inspection.Phase != "phase2") {
		return Chain{}, errors.New("chain inspection is missing a valid ceremony identity or phase")
	}
	if inspection.AcceptedCount != len(inspection.Records) {
		return Chain{}, fmt.Errorf("chain inspection count %d does not match %d records", inspection.AcceptedCount, len(inspection.Records))
	}
	for index, ref := range inspection.Artifacts {
		if err := validateRef(ref); err != nil {
			return Chain{}, fmt.Errorf("chain inspection artifact %d: %w", index, err)
		}
	}
	for index, record := range inspection.Records {
		if int(record.Index) != index+1 || record.RecordID == "" || record.ParticipantID == "" {
			return Chain{}, fmt.Errorf("chain inspection record %d has invalid identity or index", index)
		}
		for artifactIndex, ref := range record.Artifacts {
			if err := validateRef(ref); err != nil {
				return Chain{}, fmt.Errorf("chain inspection record %d artifact %d: %w", index, artifactIndex, err)
			}
		}
	}
	return Chain{
		Schema:             inspection.Schema,
		CeremonyID:         inspection.CeremonyID,
		Phase:              inspection.Phase,
		ChainPath:          chainPath,
		ChainSignaturePath: chainSignaturePath,
		Artifacts:          inspection.Artifacts,
		Records:            inspection.Records,
	}, nil
}

func (i Inspector) Participant(signingKeyPath string) (ParticipantInspection, error) {
	result, err := i.execute(
		"inspect", "participant",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--participant-signing-key", signingKeyPath,
	)
	if err != nil {
		return ParticipantInspection{}, err
	}
	if result.Command != "inspect participant" || result.ParticipantInspection == nil {
		return ParticipantInspection{}, errors.New("mpc-ceremony returned no participant inspection")
	}
	inspection := *result.ParticipantInspection
	if inspection.Schema != participantInspectionSchema || inspection.CeremonyID == "" ||
		inspection.ParticipantID == "" || inspection.KeyID == "" || inspection.PublicKeyFingerprint == "" {
		return ParticipantInspection{}, errors.New("mpc-ceremony returned an invalid participant inspection")
	}
	return inspection, nil
}

func (i Inspector) Enrollment(recordPath, signaturePath string) (EnrollmentInspection, error) {
	result, err := i.execute(
		"inspect", "enrollment",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--enrollment", recordPath,
		"--enrollment-signature", signaturePath,
	)
	if err != nil {
		return EnrollmentInspection{}, err
	}
	if result.Command != "inspect enrollment" || result.EnrollmentInspection == nil {
		return EnrollmentInspection{}, errors.New("mpc-ceremony returned no enrollment inspection")
	}
	inspection := *result.EnrollmentInspection
	if inspection.Schema != enrollmentInspectionSchema || inspection.CeremonyID == "" ||
		inspection.Identity.ID == "" || inspection.Identity.DisplayName == "" || inspection.Identity.KeyID == "" ||
		inspection.Identity.Ed25519PublicKeyHex == "" || inspection.Identity.PublicKeyFingerprint == "" ||
		inspection.Role == "" || inspection.RoleIndex < 1 || inspection.EnrolledAt == "" {
		return EnrollmentInspection{}, errors.New("mpc-ceremony returned an invalid enrollment inspection")
	}
	if err := validateRef(inspection.IndependenceDisclosure); err != nil {
		return EnrollmentInspection{}, fmt.Errorf("enrollment independence disclosure: %w", err)
	}
	return inspection, nil
}

func (i Inspector) Checkpoint(checkpointPath, signaturePath string) (CheckpointInspection, error) {
	result, err := i.execute(
		"inspect", "checkpoint",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--checkpoint", checkpointPath,
		"--checkpoint-signature", signaturePath,
	)
	if err != nil {
		return CheckpointInspection{}, err
	}
	if result.Command != "inspect checkpoint" || result.CheckpointInspection == nil {
		return CheckpointInspection{}, errors.New("mpc-ceremony returned no checkpoint inspection")
	}
	inspection := *result.CheckpointInspection
	if err := validateCheckpointInspection(inspection); err != nil {
		return CheckpointInspection{}, err
	}
	return inspection, nil
}

func (i Inspector) CheckpointTransition(previousPath, previousSignaturePath, nextPath, nextSignaturePath string) (CheckpointTransitionInspection, error) {
	result, err := i.execute(
		"inspect", "checkpoint-transition",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--previous-checkpoint", previousPath,
		"--previous-checkpoint-signature", previousSignaturePath,
		"--checkpoint", nextPath,
		"--checkpoint-signature", nextSignaturePath,
	)
	if err != nil {
		return CheckpointTransitionInspection{}, err
	}
	if result.Command != "inspect checkpoint-transition" || result.CheckpointTransitionInspection == nil {
		return CheckpointTransitionInspection{}, errors.New("mpc-ceremony returned no checkpoint transition inspection")
	}
	inspection := *result.CheckpointTransitionInspection
	if inspection.Schema != "proof-tool-mpc-checkpoint-transition-inspection-v1" ||
		inspection.CeremonyID == "" || inspection.Sequence != inspection.PreviousSequence+1 {
		return CheckpointTransitionInspection{}, errors.New("mpc-ceremony returned an invalid checkpoint transition inspection")
	}
	if err := validateCheckpointInspection(inspection.Checkpoint); err != nil {
		return CheckpointTransitionInspection{}, err
	}
	return inspection, nil
}

// CheckpointEvidence asks proof-tool to walk the fetched ancestry and
// re-derive every checkpoint from the exact signed evidence stored under
// artifactRoot. It is the only checkpoint inspection suitable for advancing
// Relay's durable high-water mark.
func (i Inspector) CheckpointEvidence(artifactRoot, checkpointPath, signaturePath string) (CheckpointEvidenceInspection, error) {
	result, err := i.execute(
		"checkpoint", "verify-stored",
		"--ceremony", i.CeremonyPath,
		"--ceremony-signature", i.CeremonySignaturePath,
		"--coordinator-public-key-file", i.CoordinatorPublicKeyPath,
		"--artifact-root", artifactRoot,
		"--checkpoint", checkpointPath,
		"--checkpoint-signature", signaturePath,
	)
	if err != nil {
		return CheckpointEvidenceInspection{}, err
	}
	if result.Command != "checkpoint verify-stored" || result.CheckpointEvidenceInspection == nil {
		return CheckpointEvidenceInspection{}, errors.New("mpc-ceremony returned no checkpoint evidence inspection")
	}
	inspection := *result.CheckpointEvidenceInspection
	if inspection.Schema != "proof-tool-mpc-checkpoint-evidence-inspection-v1" || !inspection.FullyVerified ||
		inspection.CeremonyID == "" || inspection.CheckpointDigest.SHA256 == "" || inspection.TransitionKind == "" ||
		inspection.VerifiedEvidenceBoundary == "" {
		return CheckpointEvidenceInspection{}, errors.New("mpc-ceremony did not fully verify checkpoint evidence")
	}
	return inspection, nil
}

func validateCheckpointInspection(value CheckpointInspection) error {
	if value.Schema != "proof-tool-mpc-checkpoint-inspection-v1" || value.CeremonyID == "" ||
		value.Workflow != "storage-first-v1" || value.RelayReleaseID == "" || value.Digest.SHA256 == "" {
		return errors.New("mpc-ceremony returned an invalid checkpoint inspection")
	}
	for _, ref := range append([]ArtifactRef{value.Phase1.HeadPayload, value.Phase1.Chain.Record, value.Phase1.Chain.Signature}, value.AcceptedArtifacts...) {
		if err := validateRef(ref); err != nil {
			return fmt.Errorf("checkpoint inspection artifact: %w", err)
		}
	}
	if err := validateRef(value.Definition.Record); err != nil {
		return fmt.Errorf("checkpoint definition: %w", err)
	}
	if err := validateRef(value.Definition.Signature); err != nil {
		return fmt.Errorf("checkpoint definition signature: %w", err)
	}
	if value.PreviousCheckpoint != nil {
		if err := validateRef(value.PreviousCheckpoint.Record); err != nil {
			return fmt.Errorf("previous checkpoint: %w", err)
		}
		if err := validateRef(value.PreviousCheckpoint.Signature); err != nil {
			return fmt.Errorf("previous checkpoint signature: %w", err)
		}
	}
	return nil
}

func (i Inspector) execute(args ...string) (inspectionResult, error) {
	executable := i.Executable
	if executable == "" {
		executable = "mpc-ceremony"
	}
	if i.CeremonyPath == "" || i.CeremonySignaturePath == "" || i.CoordinatorPublicKeyPath == "" {
		return inspectionResult{}, errors.New("ceremony, ceremony signature, and coordinator public key are required for inspection")
	}
	runner := i.Runner
	if runner == nil {
		runner = i.run
	}
	if runner == nil {
		runner = runInspectionCommand
	}
	stdout, stderr, runErr := runner(executable, append([]string{"--format", "json"}, args...)...)
	var result inspectionResult
	if err := json.Unmarshal(stdout, &result); err != nil {
		if runErr != nil {
			return inspectionResult{}, fmt.Errorf("mpc-ceremony inspection failed: %s", diagnostic(stderr, runErr.Error()))
		}
		return inspectionResult{}, fmt.Errorf("decode mpc-ceremony inspection: %w", err)
	}
	if result.Schema != commandResultSchema {
		return inspectionResult{}, fmt.Errorf("mpc-ceremony result schema %q, want %q", result.Schema, commandResultSchema)
	}
	if runErr != nil || !result.OK {
		message := result.Error.Message
		if message == "" {
			message = diagnostic(stderr, "inspection failed")
		}
		return inspectionResult{}, fmt.Errorf("mpc-ceremony inspection failed: %s", message)
	}
	return result, nil
}

func runInspectionCommand(executable string, args ...string) ([]byte, []byte, error) {
	command := exec.Command(executable, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func diagnostic(stderr []byte, fallback string) string {
	if message := strings.TrimSpace(string(stderr)); message != "" {
		return message
	}
	return fallback
}
