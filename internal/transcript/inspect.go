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
	Schema                string                 `json:"schema"`
	OK                    bool                   `json:"ok"`
	Command               string                 `json:"command"`
	DefinitionInspection  *Definition            `json:"definition_inspection"`
	ChainInspection       *chainInspection       `json:"chain_inspection"`
	ParticipantInspection *ParticipantInspection `json:"participant_inspection"`
	EnrollmentInspection  *EnrollmentInspection  `json:"enrollment_inspection"`
	JourneyInspection     *Journey               `json:"journey_inspection"`
	Error                 inspectionCommandError `json:"error"`
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
