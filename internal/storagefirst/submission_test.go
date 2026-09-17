package storagefirst

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func submissionInspectionFor(cp Checkpoint, slot Slot) map[string]any {
	digest := map[string]any{
		"sha256":     "sha256:" + strings.Repeat("d", 64),
		"blake2b256": "blake2b256:" + strings.Repeat("e", 64),
		"size":       32,
	}
	return map[string]any{
		"schema": "proof-tool-mpc-submission-inspection-v1", "ceremony_id": cp.CeremonyID,
		"workflow": "storage-first-v1", "relay_release_id": "role-images-test",
		"submitter_id": slot.IdentityID, "submitter_key_id": "participant-key", "submitter_role": "participant",
		"kind": slot.Kind, "phase": slot.Phase, "index": slot.Index,
		"parent_checkpoint_sha256":     slot.BasisCheckpointDigest,
		"allocation_checkpoint_sha256": cp.Position.Digest, "parent_head_id": slot.ParentHeadID,
		"attempt_id": slot.AttemptID, "manifest_key": slot.ManifestKey,
		"payloads":        []any{map[string]any{"name": "submissions/payload.bin", "digest": digest}},
		"envelope_digest": digest, "envelope_signature_digest": digest, "manifest_digest": digest,
	}
}

func TestAuthenticateObservedSubmissionRequiresExactProofToolVerification(t *testing.T) {
	cp := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	cp.CeremonyID = digestOfTest("0")
	slot := cp.Slots[0]
	projection := submissionInspectionFor(cp, slot)
	mode := "valid"
	inspector := transcript.Inspector{
		Executable: "/approved/mpc-ceremony", CeremonyPath: "/work/ceremony.json",
		CeremonySignaturePath: "/work/ceremony.sig", CoordinatorPublicKeyPath: "/trust/coordinator.hex",
		Runner: func(_ string, args ...string) ([]byte, []byte, error) {
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--attempt-id "+slot.AttemptID) ||
				!strings.Contains(joined, "--manifest /inbox/manifest.json") {
				t.Fatalf("proof-tool did not receive the exact slot and manifest: %q", args)
			}
			if mode == "forged" {
				message := "submission signature verification failed"
				raw, err := json.Marshal(map[string]any{
					"schema": "proof-tool-mpc-command-result-v1", "ok": false,
					"command": "inspect submission", "error": map[string]any{"code": "invalid_input", "message": message},
				})
				return raw, nil, err
			}
			if mode == "oversized" {
				projection["manifest_digest"] = map[string]any{
					"sha256":     "sha256:" + strings.Repeat("d", 64),
					"blake2b256": "blake2b256:" + strings.Repeat("e", 64),
					"size":       16<<20 + 1,
				}
			}
			raw, err := json.Marshal(map[string]any{
				"schema": "proof-tool-mpc-command-result-v1", "ok": true,
				"command": "inspect submission", "submission_inspection": projection,
			})
			return raw, nil, err
		},
	}
	files := SubmissionInspectionFiles{
		CheckpointPath: "/work/checkpoint.json", CheckpointSignaturePath: "/work/checkpoint.sig",
		EnvelopePath: "/inbox/envelope.json", EnvelopeSignaturePath: "/inbox/envelope.sig",
		ManifestPath: "/inbox/manifest.json",
	}
	verified, err := AuthenticateObservedSubmission(ProofToolVerifier{Inspector: inspector}, cp, slot, files)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RecommendPhase1At(cp, localFor(Coordinator, "coordinator"), ObservedSubmissions(verified), recommendationTime)
	if err != nil || got.Action != ActionAcceptReceipt || !got.Ready {
		t.Fatalf("authenticated submission did not become inspectable: %+v, %v", got, err)
	}
	replacementCheckpoint := cp
	replacementCheckpoint.Position.Digest = digestOfTest("f")
	got, err = RecommendPhase1At(replacementCheckpoint, localFor(Coordinator, "coordinator"), ObservedSubmissions(verified), recommendationTime)
	if err != nil || got.Action != ActionWaitReceipt || got.Ready {
		t.Fatalf("observation from another checkpoint advanced readiness: %+v, %v", got, err)
	}

	projection["attempt_id"] = strings.Repeat("f", 32)
	if _, err := AuthenticateObservedSubmission(ProofToolVerifier{Inspector: inspector}, cp, slot, files); err == nil {
		t.Fatal("wrong-slot proof-tool projection accepted")
	}
	projection["attempt_id"] = slot.AttemptID
	for _, rejectedMode := range []string{"forged", "oversized"} {
		mode = rejectedMode
		if _, err := AuthenticateObservedSubmission(ProofToolVerifier{Inspector: inspector}, cp, slot, files); err == nil {
			t.Fatalf("%s manifest accepted without proof-tool verification", rejectedMode)
		}
	}
}

func TestAuthenticateObservedSubmissionRejectsShallowOrUnallocatedSlot(t *testing.T) {
	cp := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	cp.CeremonyID = digestOfTest("0")
	slot := cp.Slots[0]
	verifier := ProofToolVerifier{Inspector: transcript.Inspector{Runner: func(_ string, _ ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("must not run")
	}}}
	cp.authenticatedEvidence = false
	if _, err := AuthenticateObservedSubmission(verifier, cp, slot, SubmissionInspectionFiles{}); err == nil {
		t.Fatal("shallow checkpoint accepted")
	}
	cp.authenticatedEvidence = true
	slot.Status = "accepted"
	if _, err := AuthenticateObservedSubmission(verifier, cp, slot, SubmissionInspectionFiles{}); err == nil {
		t.Fatal("unallocated slot accepted")
	}
}
