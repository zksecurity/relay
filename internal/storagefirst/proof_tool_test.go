package storagefirst

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestProofToolEvidenceUsesFetchedDefinitionInsideArtifactRoot(t *testing.T) {
	root := t.TempDir()
	digest := transcript.Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 10}
	definition := transcript.SignedArtifactRefs{
		Record:    transcript.ArtifactRef{Name: "ceremony/ceremony.json", Digest: digest},
		Signature: transcript.ArtifactRef{Name: "ceremony/ceremony.sig", Digest: digest},
	}
	inspector := transcript.Inspector{
		CeremonyPath: "original/ceremony.json", CeremonySignaturePath: "original/ceremony.sig", CoordinatorPublicKeyPath: "trust/coordinator.hex",
	}
	inspector.Runner = func(_ string, args ...string) ([]byte, []byte, error) {
		joined := strings.Join(args, " ")
		var result map[string]any
		switch {
		case strings.Contains(joined, "inspect checkpoint"):
			result = map[string]any{
				"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "inspect checkpoint",
				"checkpoint_inspection": map[string]any{
					"schema": "proof-tool-mpc-checkpoint-inspection-v1", "ceremony_id": "sha256:" + strings.Repeat("c", 64),
					"workflow": "storage-first-v1", "relay_release_id": "release", "sequence": 0, "digest": digest,
					"definition": definition, "transition": map[string]any{"kind": "initial"},
					"phase1":             map[string]any{"phase": "phase1", "accepted_count": 0, "head_record_id": "sha256:" + strings.Repeat("d", 64), "head_payload": transcript.ArtifactRef{Name: "phase1/genesis.bin", Digest: digest}, "chain": transcript.SignedArtifactRefs{Record: transcript.ArtifactRef{Name: "phase1/chain-0000.json", Digest: digest}, Signature: transcript.ArtifactRef{Name: "phase1/chain-0000.sig", Digest: digest}}},
					"accepted_artifacts": []transcript.ArtifactRef{definition.Record, definition.Signature, {Name: "phase1/genesis.bin", Digest: digest}},
				},
			}
		case strings.Contains(joined, "checkpoint verify-stored"):
			wantCeremony := "--ceremony " + filepath.Join(root, "ceremony/ceremony.json")
			wantSignature := "--ceremony-signature " + filepath.Join(root, "ceremony/ceremony.sig")
			if !strings.Contains(joined, wantCeremony) || !strings.Contains(joined, wantSignature) {
				t.Fatalf("deep verification did not use fetched definition: %s", joined)
			}
			result = map[string]any{
				"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "checkpoint verify-stored",
				"checkpoint_evidence_inspection": map[string]any{
					"schema": "proof-tool-mpc-checkpoint-evidence-inspection-v1", "ceremony_id": "sha256:" + strings.Repeat("c", 64),
					"sequence": 0, "checkpoint_digest": digest, "transition_kind": "initial", "fully_verified": true, "verified_evidence_boundary": "cp0",
				},
			}
		default:
			t.Fatalf("unexpected args: %s", joined)
		}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	got, err := (ProofToolVerifier{Inspector: inspector}).VerifyEvidence(root, filepath.Join(root, "checkpoints/0.json"), filepath.Join(root, "checkpoints/0.sig"))
	if err != nil || !got.FullyVerified {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestProofToolCheckpointProjectsBothPhasesAndFinalState(t *testing.T) {
	digest := transcript.Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 10}
	ref := func(name string) transcript.ArtifactRef { return transcript.ArtifactRef{Name: name, Digest: digest} }
	signed := func(name string) *transcript.SignedArtifactRefs {
		return &transcript.SignedArtifactRefs{Record: ref(name + ".json"), Signature: ref(name + ".sig")}
	}
	definition := transcript.Definition{Schema: "proof-tool-mpc-definition-inspection-v1", CeremonyID: "sha256:" + strings.Repeat("c", 64), Mode: "rehearsal", Phase1Participants: []string{"participant-1"}, Phase2Participants: []string{"participant-1"}, R1CSRef: ref("circuit.ccs")}
	inspection := transcript.CheckpointInspection{
		Schema: "proof-tool-mpc-checkpoint-inspection-v1", CeremonyID: definition.CeremonyID,
		Workflow: "storage-first-v1", RelayReleaseID: "release", Sequence: 14, Digest: digest,
		Definition: *signed("ceremony"), Transition: transcript.CheckpointTransition{Kind: "final-release-recorded"},
		Phase1:        transcript.CheckpointPhaseState{Phase: "phase1", AcceptedCount: 1, HeadRecordID: "sha256:" + strings.Repeat("1", 64), HeadPayload: ref("phase1/head.bin"), Chain: *signed("phase1/chain")},
		Phase1Closure: signed("phase1/close"), Phase1Beacon: signed("phase1/beacon"), Phase1Seal: signed("phase1/seal"),
		Phase2:        &transcript.CheckpointPhaseState{Phase: "phase2", AcceptedCount: 1, HeadRecordID: "sha256:" + strings.Repeat("2", 64), HeadPayload: ref("phase2/head.bin"), Chain: *signed("phase2/chain")},
		Phase2Closure: signed("phase2/close"), Phase2Beacon: signed("phase2/beacon"),
		FinalCandidate: signed("final/candidate"), FinalRelease: signed("final/release"),
	}
	inspector := transcript.Inspector{CeremonyPath: "ceremony.json", CeremonySignaturePath: "ceremony.sig", CoordinatorPublicKeyPath: "coordinator.hex"}
	inspector.Runner = func(_ string, args ...string) ([]byte, []byte, error) {
		var result any
		if strings.Contains(strings.Join(args, " "), "inspect definition") {
			result = map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "inspect definition", "definition_inspection": definition}
		} else {
			result = map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": "inspect checkpoint", "checkpoint_inspection": inspection}
		}
		raw, _ := json.Marshal(result)
		return raw, nil, nil
	}
	got, err := (ProofToolVerifier{Inspector: inspector}).VerifyCheckpoint("checkpoint.json", "checkpoint.sig")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Phase1Closed || !got.Phase2Closed || got.Phase2Accepted != 1 || !got.FinalCandidateRecorded || !got.FinalReleaseRecorded || !got.Position.PhaseHeads["phase2"].Closed {
		t.Fatalf("incomplete lifecycle projection: %+v", got)
	}
}
