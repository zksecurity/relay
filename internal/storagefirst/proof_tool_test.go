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
