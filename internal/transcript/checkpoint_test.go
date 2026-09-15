package transcript

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func checkpointInspectionFixture() CheckpointInspection {
	digest := Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Blake2b256: "blake2b256:" + strings.Repeat("b", 64), Size: 10}
	artifact := ArtifactRef{Name: "phase1/genesis.bin", Digest: digest}
	definition := SignedArtifactRefs{Record: ArtifactRef{Name: "ceremony.json", Digest: digest}, Signature: ArtifactRef{Name: "ceremony.sig", Digest: digest}}
	return CheckpointInspection{
		Schema: "proof-tool-mpc-checkpoint-inspection-v1", CeremonyID: "sha256:" + strings.Repeat("c", 64),
		Workflow: "storage-first-v1", RelayReleaseID: "role-images-release", Sequence: 0, Digest: digest,
		Transition: CheckpointTransition{Kind: "initial"},
		Definition: definition,
		Phase1: CheckpointPhaseState{Phase: "phase1", HeadRecordID: "sha256:" + strings.Repeat("d", 64), HeadPayload: artifact,
			Chain: SignedArtifactRefs{Record: ArtifactRef{Name: "phase1/chain-0000.json", Digest: digest}, Signature: ArtifactRef{Name: "phase1/chain-0000.sig", Digest: digest}}},
		AcceptedArtifacts: []ArtifactRef{artifact},
	}
}

func TestCheckpointUsesProofToolProjection(t *testing.T) {
	want := checkpointInspectionFixture()
	digest := want.Digest
	want.Phase1Closure = &SignedArtifactRefs{Record: ArtifactRef{Name: "phase1/close.json", Digest: digest}, Signature: ArtifactRef{Name: "phase1/close.sig", Digest: digest}}
	want.Phase1Beacon = &SignedArtifactRefs{Record: ArtifactRef{Name: "phase1/beacon.json", Digest: digest}, Signature: ArtifactRef{Name: "phase1/beacon.sig", Digest: digest}}
	want.Phase1Seal = &SignedArtifactRefs{Record: ArtifactRef{Name: "phase1/seal.json", Digest: digest}, Signature: ArtifactRef{Name: "phase1/seal.sig", Digest: digest}}
	want.Phase2 = &CheckpointPhaseState{Phase: "phase2", HeadRecordID: "sha256:" + strings.Repeat("e", 64), HeadPayload: ArtifactRef{Name: "phase2/genesis.bin", Digest: digest}, Chain: SignedArtifactRefs{Record: ArtifactRef{Name: "phase2/chain-0000.json", Digest: digest}, Signature: ArtifactRef{Name: "phase2/chain-0000.sig", Digest: digest}}}
	want.Phase2Closure = &SignedArtifactRefs{Record: ArtifactRef{Name: "phase2/close.json", Digest: digest}, Signature: ArtifactRef{Name: "phase2/close.sig", Digest: digest}}
	want.Phase2Beacon = &SignedArtifactRefs{Record: ArtifactRef{Name: "phase2/beacon.json", Digest: digest}, Signature: ArtifactRef{Name: "phase2/beacon.sig", Digest: digest}}
	want.FinalCandidate = &SignedArtifactRefs{Record: ArtifactRef{Name: "final/candidate.json", Digest: digest}, Signature: ArtifactRef{Name: "final/candidate.sig", Digest: digest}}
	want.FinalRelease = &SignedArtifactRefs{Record: ArtifactRef{Name: "final/release.json", Digest: digest}, Signature: ArtifactRef{Name: "final/release.sig", Digest: digest}}
	inspector := Inspector{CeremonyPath: "ceremony.json", CeremonySignaturePath: "ceremony.sig", CoordinatorPublicKeyPath: "coordinator.hex"}
	inspector.Runner = func(_ string, args ...string) ([]byte, []byte, error) {
		if strings.Join(args, " ") != "--format json inspect checkpoint --ceremony ceremony.json --ceremony-signature ceremony.sig --coordinator-public-key-file coordinator.hex --checkpoint checkpoint.json --checkpoint-signature checkpoint.sig" {
			t.Fatalf("args=%q", args)
		}
		result := inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect checkpoint", CheckpointInspection: &want}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	got, err := inspector.Checkpoint("checkpoint.json", "checkpoint.sig")
	if err != nil || got.Sequence != 0 || got.Workflow != "storage-first-v1" || got.Phase2 == nil || got.FinalRelease == nil {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestCheckpointRejectsMissingOrMalformedProjection(t *testing.T) {
	inspector := Inspector{CeremonyPath: "ceremony.json", CeremonySignaturePath: "ceremony.sig", CoordinatorPublicKeyPath: "coordinator.hex"}
	inspector.Runner = func(_ string, _ ...string) ([]byte, []byte, error) {
		result := inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect checkpoint"}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	if _, err := inspector.Checkpoint("checkpoint.json", "checkpoint.sig"); err == nil {
		t.Fatal("missing projection accepted")
	}
	bad := checkpointInspectionFixture()
	bad.AcceptedArtifacts[0].Name = "../escape"
	inspector.Runner = func(_ string, _ ...string) ([]byte, []byte, error) {
		result := inspectionResult{Schema: commandResultSchema, OK: true, Command: "inspect checkpoint", CheckpointInspection: &bad}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	if _, err := inspector.Checkpoint("checkpoint.json", "checkpoint.sig"); err == nil {
		t.Fatal("unsafe proof-tool projection accepted")
	}
}

func TestCheckpointTransitionPropagatesProofToolRejection(t *testing.T) {
	inspector := Inspector{CeremonyPath: "ceremony.json", CeremonySignaturePath: "ceremony.sig", CoordinatorPublicKeyPath: "coordinator.hex"}
	inspector.Runner = func(_ string, _ ...string) ([]byte, []byte, error) {
		result := inspectionResult{Schema: commandResultSchema, OK: false, Command: "inspect checkpoint-transition"}
		result.Error.Message = "checkpoint parent mismatch"
		raw, _ := json.Marshal(result)
		return raw, nil, errors.New("exit 6")
	}
	if _, err := inspector.CheckpointTransition("p.json", "p.sig", "n.json", "n.sig"); err == nil || !strings.Contains(err.Error(), "parent mismatch") {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckpointEvidenceRequiresFullVerifiedProjection(t *testing.T) {
	inspector := Inspector{CeremonyPath: "ceremony.json", CeremonySignaturePath: "ceremony.sig", CoordinatorPublicKeyPath: "coordinator.hex"}
	want := CheckpointEvidenceInspection{
		Schema: "proof-tool-mpc-checkpoint-evidence-inspection-v1", CeremonyID: "sha256:" + strings.Repeat("c", 64),
		Sequence: 3, CheckpointDigest: Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 10},
		TransitionKind: "phase1-candidate-accepted", FullyVerified: true, VerifiedEvidenceBoundary: "cp0-cp3",
	}
	inspector.Runner = func(_ string, args ...string) ([]byte, []byte, error) {
		if strings.Join(args, " ") != "--format json checkpoint verify-stored --ceremony ceremony.json --ceremony-signature ceremony.sig --coordinator-public-key-file coordinator.hex --artifact-root artifacts --checkpoint checkpoint.json --checkpoint-signature checkpoint.sig" {
			t.Fatalf("args=%q", args)
		}
		result := inspectionResult{Schema: commandResultSchema, OK: true, Command: "checkpoint verify-stored", CheckpointEvidenceInspection: &want}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	got, err := inspector.CheckpointEvidence("artifacts", "checkpoint.json", "checkpoint.sig")
	if err != nil || !got.FullyVerified || got.Sequence != 3 {
		t.Fatalf("got=%+v err=%v", got, err)
	}

	want.FullyVerified = false
	if _, err := inspector.CheckpointEvidence("artifacts", "checkpoint.json", "checkpoint.sig"); err == nil {
		t.Fatal("non-full evidence projection accepted")
	}
}
