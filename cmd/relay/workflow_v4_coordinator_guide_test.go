package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4CoordinatorIntentIsStableAndCheckpointStaysPublic(t *testing.T) {
	work := t.TempDir()
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "participant", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	pair := pairV4Test("head")
	path := filepath.Join(workflowV4CoordinatorTurnDir(work, scope), "allocation-intent.json")
	output := workflowV4CoordinatorCheckpointDir(work, scope, "allocate", "basis")
	first, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", pair, scope, "", output)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", pair, scope, "", output)
	if err != nil || second != first {
		t.Fatalf("unstable intent: first=%+v second=%+v err=%v", first, second, err)
	}
	public := filepath.Join(work, "ceremony", "public")
	if relative, err := filepath.Rel(public, first.OutputDir); err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("checkpoint output escaped public artifact root: %s", first.OutputDir)
	}
	changed := pair
	changed.Record.Digest.SHA256 = "sha256:" + strings.Repeat("3", 64)
	if _, err := loadOrCreateWorkflowV4CoordinatorIntent(path, "allocate", changed, scope, "", output); err == nil {
		t.Fatal("retained intent was silently rebound to another predecessor")
	}
}

func TestWorkflowV4CoordinatorCheckpointCommandsUseMountedPaths(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{filepath.Join(work, "ceremony", "public"), filepath.Join(trust), filepath.Join(keys)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	online := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys}
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "p", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	intent := workflowV4CoordinatorIntent{Action: "allocate", Scope: scope, AttemptID: strings.Repeat("a", 32), At: "2026-09-16T00:00:00Z", OutputDir: workflowV4CoordinatorCheckpointDir(work, scope, "allocate", "basis")}
	head := pairV4Test("head")
	command, err := workflowV4CheckpointCommand(signer, online, head, intent, "allocate-v4", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{"checkpoint allocate-v4", "--artifact-root /work/ceremony/public", "--coordinator-signing-key /keys/signing.hex", "--attempt-id " + intent.AttemptID} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q lacks %q", joined, want)
		}
	}
}

func TestWorkflowV4CoordinatorRejectCommandUsesExactPrivateCandidate(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{filepath.Join(work, "ceremony", "public"), filepath.Join(work, "workflow-v4", "candidate"), trust, keys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	online := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys}
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "p", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	head := pairV4Test("head")
	candidate := filepath.Join(work, "workflow-v4", "candidate")
	intent := workflowV4CoordinatorIntent{Action: "reject", Scope: scope, AttemptID: strings.Repeat("a", 32), OutputDir: workflowV4CoordinatorCheckpointDir(work, scope, "reject", strings.Repeat("a", 32))}
	command, err := workflowV4CheckpointCommand(signer, online, head, intent, "reject-candidate-v4", candidate)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{"checkpoint reject-candidate-v4", "--rejected-candidate-dir /work/workflow-v4/candidate", "--attempt-id " + intent.AttemptID} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q lacks %q", joined, want)
		}
	}
	if strings.Contains(joined, "--accepted-at") || strings.Contains(joined, "--candidate-dir") {
		t.Fatalf("rejection command incorrectly looks like acceptance: %q", joined)
	}
	if _, err := workflowV4CheckpointCommand(signer, online, head, intent, "reject-candidate-v4", ""); err == nil {
		t.Fatal("rejection accepted an empty candidate directory")
	}
}

func TestWorkflowV4CoordinatorRejectLabelIsExplicit(t *testing.T) {
	got := workflowV4CoordinatorActionLabel(storagefirst.TurnRecommendationV4{Action: "review-and-reject-candidate"}, workflowV4CoordinatorProgress{CandidateInspectionError: "bad signature"})
	if got != "Review the received candidate and reject it if appropriate" {
		t.Fatalf("label = %q", got)
	}
}

func TestWorkflowV4CoordinatorInspectionFailureIsReviewable(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "received-candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "p", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	phase := transcript.CheckpointPhaseState{Chain: pairV4Test("head")}
	inspector := transcript.Inspector{
		CeremonyPath:             filepath.Join(root, "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(root, "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(root, "coordinator.hex"),
		TranscriptRoot:           root,
		Runner: func(_ string, _ ...string) ([]byte, []byte, error) {
			return []byte(`{"schema":"proof-tool-mpc-command-result-v1","ok":false,"command":"inspect contribution-inventory-v4","error":{"code":"candidate_invalid","message":"candidate signature is invalid"}}`), nil, errors.New("exit status 6")
		},
	}
	inventory, inspectionErr, err := workflowV4CoordinatorInspectCandidate(inspector, phase, filepath.Join(root, "scope.json"), candidate, scope)
	if err != nil || inventory != nil || inspectionErr == "" {
		t.Fatalf("inventory=%+v inspectionErr=%q err=%v", inventory, inspectionErr, err)
	}
	turn := storagefirst.TurnViewV4{Scope: scope, CandidateAttempt: &transcript.DeliverySlotV4{AttemptID: strings.Repeat("a", 32)}}
	recommendation, ok := workflowV4CoordinatorCandidateRecommendation(turn, workflowV4CoordinatorProgress{CandidateDir: candidate, CandidateInspectionError: inspectionErr})
	if !ok || recommendation.Action != "review-and-reject-candidate" || !recommendation.Ready || recommendation.Scope != scope || recommendation.AttemptID != turn.CandidateAttempt.AttemptID {
		t.Fatalf("recommendation = %+v, ok=%v", recommendation, ok)
	}
	if _, ok := workflowV4CoordinatorCandidateRecommendation(turn, workflowV4CoordinatorProgress{CandidateDir: candidate}); ok {
		t.Fatal("candidate without an inspection error became rejectable")
	}
	inspector.Runner = func(_ string, _ ...string) ([]byte, []byte, error) {
		return []byte(`{"schema":"proof-tool-mpc-command-result-v1","ok":false,"command":"inspect contribution-inventory-v4","error":{"code":"internal_error","message":"candidate path is unavailable"}}`), nil, errors.New("exit status 6")
	}
	if _, candidateErr, err := workflowV4CoordinatorInspectCandidate(inspector, phase, filepath.Join(root, "scope.json"), candidate, scope); err == nil || candidateErr != "" {
		t.Fatalf("operational inspection error was made rejectable: candidateErr=%q err=%v", candidateErr, err)
	}
}

func TestWorkflowV4CandidateFetchReceiptRequiresExactRetainedFiles(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := transcript.ContributionScopeV4{CeremonyID: "sha256:" + strings.Repeat("1", 64), Phase: "phase1", Index: 1, ParticipantID: "p", ParentHeadID: "sha256:" + strings.Repeat("2", 64)}
	attempt := strings.Repeat("a", 32)
	files := map[string][]byte{
		"attestation.json": []byte("attestation"),
		"attestation.sig":  []byte("attestation signature"),
		"contribution.bin": []byte("contribution"),
		"erasure.json":     []byte("erasure"),
		"erasure.sig":      []byte("erasure signature"),
	}
	receipt := workflowV4CandidateFetchReceipt{Schema: workflowV4CandidateFetchReceiptSchema, CeremonyID: scope.CeremonyID, AttemptID: attempt, Kind: "candidate", Manifest: state.ContentRef{Name: "manifest.json", SHA256: "sha256:" + strings.Repeat("b", 64), Size: 1}}
	for name, raw := range files {
		path := filepath.Join(candidate, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		sha, size, err := transcript.DigestFile(path)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Files = append(receipt.Files, state.ContentRef{Name: name, SHA256: sha, Size: size})
	}
	if err := writeJSONNoReplace(workflowV4CandidateFetchReceiptPath(candidate), receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkflowV4CandidateFetchReceipt(candidate, scope, attempt); err != nil {
		t.Fatalf("valid fetched package rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "contribution.bin"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkflowV4CandidateFetchReceipt(candidate, scope, attempt); err == nil {
		t.Fatal("changed retained candidate became rejectable")
	}
	if err := os.Remove(workflowV4CandidateFetchReceiptPath(candidate)); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkflowV4CandidateFetchReceipt(candidate, scope, attempt); err == nil {
		t.Fatal("candidate without a transport receipt became rejectable")
	}
}

func TestQuarantineWorkflowV4CandidateDownloadPreservesIncompleteAttempt(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "candidates", "attempt")
	if err := os.MkdirAll(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "contribution.bin"), []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflowV4CandidateFetchReceiptPath(candidate), []byte(`{"schema":"incomplete"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := quarantineWorkflowV4CandidateDownload(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate remains in the fresh output location: %v", err)
	}
	if _, err := os.Stat(filepath.Join(retained, "candidate", "contribution.bin")); err != nil {
		t.Fatalf("candidate was not preserved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(retained, "transport-receipt.json")); err != nil {
		t.Fatalf("receipt was not preserved: %v", err)
	}
}

func pairV4Test(seed string) transcript.SignedArtifactRefs {
	digest := func(s string) transcript.Digest {
		return transcript.Digest{SHA256: "sha256:" + strings.Repeat(s, 64), Blake2b256: "blake2b256:" + strings.Repeat(s, 64), Size: 10}
	}
	return transcript.SignedArtifactRefs{Record: transcript.ArtifactRef{Name: "checkpoints/" + seed + "/checkpoint.json", Digest: digest("a")}, Signature: transcript.ArtifactRef{Name: "checkpoints/" + seed + "/checkpoint.sig", Digest: digest("b")}}
}
