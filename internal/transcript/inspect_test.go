package transcript

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func inspectionTestRef(name string) ArtifactRef {
	return ArtifactRef{
		Name: name,
		Digest: Digest{
			SHA256:     "sha256:" + hex64,
			Blake2b256: "blake2b256:" + hex64,
			Size:       1,
		},
	}
}

func inspectionTestRunner(t *testing.T, result inspectionResult, wantCommand string) inspectionRunner {
	t.Helper()
	return func(executable string, args ...string) ([]byte, []byte, error) {
		t.Helper()
		if executable != "/trusted/mpc-ceremony" {
			t.Fatalf("executable = %q", executable)
		}
		if len(args) < 4 || args[0] != "--format" || args[1] != "json" || strings.Join(args[2:4], " ") != wantCommand {
			t.Fatalf("args = %q", args)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return encoded, nil, nil
	}
}

func testInspector() Inspector {
	return Inspector{
		Executable:               "/trusted/mpc-ceremony",
		CeremonyPath:             "/ceremony/ceremony.json",
		CeremonySignaturePath:    "/ceremony/ceremony.sig",
		CoordinatorPublicKeyPath: "/trust/coordinator.pub",
		TranscriptRoot:           "/ceremony",
	}
}

func TestInspectorReadsAuthenticatedDefinitionProjection(t *testing.T) {
	want := testDefinition()
	inspector := testInspector()
	inspector.run = inspectionTestRunner(t, inspectionResult{
		Schema:               commandResultSchema,
		OK:                   true,
		Command:              "inspect definition",
		DefinitionInspection: &want,
	}, "inspect definition")

	got, err := inspector.Definition()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("definition = %#v, want %#v", got, want)
	}
}

func TestInspectorReadsAuthenticatedChainProjection(t *testing.T) {
	chain := &chainInspection{
		Schema:        chainInspectionSchema,
		CeremonyID:    "ceremony-id",
		Phase:         "phase1",
		AcceptedCount: 1,
		Artifacts:     []ArtifactRef{inspectionTestRef("phase1/genesis.bin"), inspectionTestRef("phase1/output.bin")},
		Records: []ChainRecord{{
			Index:         1,
			RecordID:      "record-id",
			ParticipantID: "participant-01",
			Artifacts:     []ArtifactRef{inspectionTestRef("phase1/output.bin")},
		}},
	}
	inspector := testInspector()
	inspector.run = inspectionTestRunner(t, inspectionResult{
		Schema:          commandResultSchema,
		OK:              true,
		Command:         "inspect chain",
		ChainInspection: chain,
	}, "inspect chain")

	got, err := inspector.Chain("/ceremony/phase1/chain-0001.json", "/ceremony/phase1/chain-0001.sig")
	if err != nil {
		t.Fatal(err)
	}
	if got.AcceptedCount() != 1 || got.ChainPath != "/ceremony/phase1/chain-0001.json" ||
		got.ChainSignaturePath != "/ceremony/phase1/chain-0001.sig" {
		t.Fatalf("chain = %#v", got)
	}
}

func TestInspectorReadsProofToolParticipantProjection(t *testing.T) {
	position := uint8(3)
	want := ParticipantInspection{
		Schema: participantInspectionSchema, CeremonyID: "ceremony-id",
		ParticipantID: "participant-03", KeyID: "participant-03-key",
		PublicKeyFingerprint: "sha256:" + hex64, Phase1Position: &position,
	}
	inspector := testInspector()
	inspector.run = inspectionTestRunner(t, inspectionResult{
		Schema: commandResultSchema, OK: true, Command: "inspect participant",
		ParticipantInspection: &want,
	}, "inspect participant")

	got, err := inspector.Participant("/secure/participant.key")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("participant = %#v, want %#v", got, want)
	}
}

func TestInspectorReadsProofToolEnrollmentProjection(t *testing.T) {
	want := EnrollmentInspection{
		Schema: enrollmentInspectionSchema, CeremonyID: "ceremony-id",
		Identity: PublicIdentity{ID: "mirror-01", DisplayName: "Mirror One", KeyID: "mirror-key",
			Ed25519PublicKeyHex: strings.Repeat("a", 64), PublicKeyFingerprint: "sha256:" + hex64},
		Role: "mirror-operator", RoleIndex: 1,
		IndependenceDisclosure: inspectionTestRef("operations/disclosures/mirror-01.json"),
		EnrolledAt:             "2026-08-18T12:00:00Z",
	}
	inspector := testInspector()
	inspector.run = inspectionTestRunner(t, inspectionResult{
		Schema: commandResultSchema, OK: true, Command: "inspect enrollment",
		EnrollmentInspection: &want,
	}, "inspect enrollment")

	got, err := inspector.Enrollment("enrollment.json", "enrollment.sig")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enrollment = %#v, want %#v", got, want)
	}
}

func TestInspectorRejectsUnsafeProjection(t *testing.T) {
	chain := &chainInspection{
		Schema:        chainInspectionSchema,
		CeremonyID:    "ceremony-id",
		Phase:         "phase1",
		AcceptedCount: 0,
		Artifacts:     []ArtifactRef{inspectionTestRef("../escape")},
		Records:       []ChainRecord{},
	}
	inspector := testInspector()
	inspector.run = inspectionTestRunner(t, inspectionResult{
		Schema:          commandResultSchema,
		OK:              true,
		Command:         "inspect chain",
		ChainInspection: chain,
	}, "inspect chain")

	if _, err := inspector.Chain("/ceremony/phase1/chain-0000.json", "/ceremony/phase1/chain-0000.sig"); err == nil {
		t.Fatal("accepted an inspection containing a path escape")
	}
}

func TestInspectorReportsCommandFailure(t *testing.T) {
	inspector := testInspector()
	inspector.run = func(string, ...string) ([]byte, []byte, error) {
		result := inspectionResult{
			Schema:  commandResultSchema,
			Command: "inspect definition",
			Error: inspectionCommandError{
				Code:    "internal_error",
				Message: "signature verification failed",
			},
		}
		encoded, _ := json.Marshal(result)
		return encoded, nil, errors.New("exit status 6")
	}
	if _, err := inspector.Definition(); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error = %v", err)
	}
}
