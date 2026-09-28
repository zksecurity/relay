package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// Opt-in qualification of a copied V5 final-release snapshot. This test reads
// only the isolated fixture path supplied by the operator; it never mutates the
// ceremony from which that copy was made.
func TestDecisionReplacementAuthenticateRealFinalFixture(t *testing.T) {
	base := os.Getenv("RELAY_DECISION_REAL_FIXTURE")
	if base == "" {
		t.Skip("set RELAY_DECISION_REAL_FIXTURE to an isolated coordinator copy")
	}
	if _, err := os.Stat(filepath.Join(base, ".relay-decision-fixture-copy")); err != nil {
		t.Fatal("refuse to use a coordinator workspace without the isolated-copy marker")
	}
	work := filepath.Join(base, "work")
	public := filepath.Join(work, "ceremony", "public")
	var marker workflowV4Marker
	if err := readWorkflowV4JSON(filepath.Join(work, ".relay-workspace-v4.json"), &marker); err != nil {
		t.Fatal(err)
	}
	var definition struct {
		CeremonyID string `json:"ceremony_id"`
	}
	definitionRaw, err := os.ReadFile(filepath.Join(public, "ceremony.json"))
	if err != nil || json.Unmarshal(definitionRaw, &definition) != nil || definition.CeremonyID == "" {
		t.Fatal("fixture definition is unavailable")
	}
	if marker.Binding.CeremonyID != definition.CeremonyID {
		t.Fatal("fixture marker and signed definition name different ceremonies")
	}
	objects := guidePhaseObjects{}
	if err := filepath.WalkDir(public, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("fixture contains a non-regular public entry")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		objects[store.Key("sha256:"+hex.EncodeToString(digest[:]))] = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := filepath.Glob(filepath.Join(public, "checkpoints", "final", "release-*", "checkpoint.json"))
	if err != nil || len(checkpoints) != 1 {
		t.Fatal("fixture needs exactly one signed final-release checkpoint")
	}
	contentRef := func(path string) state.ContentRef {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(public, path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		return state.ContentRef{Name: filepath.ToSlash(rel), SHA256: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(raw))}
	}
	checkpoint := checkpoints[0]
	root := state.Root{Schema: state.RootSchema, CeremonyID: definition.CeremonyID, Checkpoint: contentRef(checkpoint), CheckpointSignature: contentRef(strings.TrimSuffix(checkpoint, ".json") + ".sig")}
	rootRaw, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	objects[state.RootKey(definition.CeremonyID)] = rootRaw
	online := marker.Binding.Runtimes["online"]
	if online.Image == "" || online.Platform == "" {
		t.Fatal("fixture lacks pinned online runtime")
	}
	driver := dockerDriver{image: online.Image, platform: online.Platform, ceremonyBinary: dockerCeremonyBinary, root: public, inspectionRoot: work, definition: filepath.Join(public, "ceremony.json"), definitionSig: filepath.Join(public, "ceremony.sig"), coordinatorKey: filepath.Join(base, "trust", "setup-coordinator.hex"), client: osDockerCommandClient{binary: "docker"}}
	inspector := driver.inspector()
	// This opt-in test runs the driver's exact read-only, bounded container
	// arguments directly. An unrelated stale Docker container may block Relay's
	// aggregate admission, but it does not affect signed-byte verification here.
	inspector.Runner = func(executable string, args ...string) ([]byte, []byte, error) {
		if executable != dockerCeremonyBinary {
			return nil, nil, errors.New("unexpected pinned verifier executable")
		}
		rewritten, mounts, err := driver.rewriteReadOnlyArgs(args)
		if err != nil {
			return nil, nil, err
		}
		command := append(driver.baseRunArgs(true, mounts), driver.image)
		command = append(command, rewritten...)
		run := exec.Command("docker", command...)
		var stdout, stderr bytes.Buffer
		run.Stdout, run.Stderr = &stdout, &stderr
		err = run.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatalf("pinned definition authentication: %v", err)
	}
	if protocol.DefinitionSchema != "proof-tool-mpc-ceremony-definition-v5" || protocol.Definition.Mode != "production" {
		t.Fatal("fixture is not a production V5 definition")
	}
	highWater, err := state.OpenWorkspaceHighWater(t.TempDir(), definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	tempParent, err := os.MkdirTemp(work, ".signed-fixture-inspection-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempParent) })
	snapshot, err := storagefirst.SyncV4Retained(objects, inspector, highWater, definition.CeremonyID, tempParent, public)
	if err != nil {
		t.Fatalf("pinned signed-checkpoint authentication: %v", err)
	}
	signed, err := snapshot.State()
	if err != nil || signed.Progress.FinalRelease == nil || signed.Transition.Kind != "final-release-recorded" {
		t.Fatalf("fixture did not authenticate the signed final release: state=%v sequence=%d transition=%s", err, signed.Sequence, signed.Transition.Kind)
	}
	t.Logf("authenticated production-mode V5 test release %s at signed update %d with %d retained public files", definition.CeremonyID, signed.Sequence, len(snapshot.Files()))
	if os.Getenv("RELAY_UPGRADE_RELEASE_SNAPSHOT_TEST") == "1" {
		if os.Getenv("RELAY_DECISION_FIXTURE_MUTATION_OK") != "1" {
			t.Fatal("set explicit mutation consent for the isolated fixture only")
		}
		handoff, err := os.ReadFile(filepath.Join(work, "smoke-release-snapshot-20", offlineSnapshotFile))
		if err != nil {
			t.Fatal(err)
		}
		manifestPath := workflowV4ReleaseSnapshotManifestPath(work)
		if err := os.MkdirAll(filepath.Dir(manifestPath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, handoff, 0600); err != nil {
			t.Fatal(err)
		}
		accepted := map[string]transcript.CheckpointInspectionV4{}
		publicRefs := map[string]transcript.ArtifactRef{}
		for pair := snapshot.Head(); ; {
			checked, err := inspector.StoredCheckpointV4(public, filepath.Join(public, filepath.FromSlash(pair.Record.Name)), filepath.Join(public, filepath.FromSlash(pair.Signature.Name)))
			if err != nil {
				t.Fatal(err)
			}
			accepted[pair.Record.Name] = checked
			for _, ref := range []transcript.ArtifactRef{pair.Record, pair.Signature, checked.Checkpoint.Definition.Record, checked.Checkpoint.Definition.Signature} {
				publicRefs[ref.Name] = ref
			}
			required, err := transcript.RequiredPublicArtifactsV4(checked)
			if err != nil {
				t.Fatal(err)
			}
			for _, ref := range required {
				publicRefs[ref.Name] = ref
			}
			if checked.Checkpoint.PreviousCheckpoint == nil {
				break
			}
			pair = *checked.Checkpoint.PreviousCheckpoint
		}
		inv := upgradeInventory{Files: []upgradeInventoryFile{{Name: "workflow-v4/coordinator/release/snapshot-manifest.json", SHA256: decisionReplacementDigest(handoff)[7:], Size: int64(len(handoff))}}}
		for _, ref := range snapshot.Files() {
			inv.Files = append(inv.Files, upgradeInventoryFile{Name: "ceremony/public/" + ref.Name, SHA256: strings.TrimPrefix(ref.SHA256, "sha256:"), Size: ref.Size})
		}
		allowed, err := upgradeCompletedReleaseSnapshotManifest(guidedProfile{Role: "coordinator", Work: work}, inv, accepted, publicRefs)
		if err != nil || !allowed {
			t.Fatalf("real signed H snapshot rejected: %v", err)
		}
		t.Log("completed H snapshot matched the pinned signed release-review ancestry and retained public files")
	}
	if os.Getenv("RELAY_DECISION_REAL_LIFECYCLE") != "1" {
		return
	}
	if os.Getenv("RELAY_DECISION_FIXTURE_MUTATION_OK") != "1" {
		t.Fatal("set explicit mutation consent for the isolated fixture only")
	}
	onlineProfile := guidedProfile{Role: "coordinator", Work: work, Trust: filepath.Join(base, "trust"), Keys: filepath.Join(base, "keys"), Image: online.Image, Platform: online.Platform}
	signing := marker.Binding.Runtimes["signer"]
	if signing.Image == "" || signing.Platform == "" {
		t.Fatal("fixture lacks pinned signing runtime")
	}
	signerProfile := guidedProfile{Role: "decision-signer", Work: work, Trust: onlineProfile.Trust, Keys: onlineProfile.Keys, Image: signing.Image, Platform: signing.Platform}
	previousExecutor := workflowV4ChildExecutor
	defer func() { workflowV4ChildExecutor = previousExecutor }()
	proofCalls := 0
	failNextPreparation := false
	workflowV4ChildExecutor = func(launch []string) error {
		separator := -1
		for i, arg := range launch {
			if arg == "--" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+1 >= len(launch) {
			return errors.New("missing pinned proof command")
		}
		command := launch[separator+1:]
		if len(command) < 3 || command[0] != "mpc-ceremony" || command[1] != "decision" || command[2] != "prepare" {
			return errors.New("unexpected proof command during replacement qualification")
		}
		proofCalls++
		if failNextPreparation {
			failNextPreparation = false
			return errors.New("test-only pinned preparation failure")
		}
		options := dockerRoleOptions{role: signerProfile.Role, image: signerProfile.Image, platform: signerProfile.Platform, work: signerProfile.Work, trust: signerProfile.Trust, keys: signerProfile.Keys}
		argv, err := dockerRoleArgs(options, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		output, err := exec.Command("docker", argv...).CombinedOutput()
		if err != nil {
			return errors.New("pinned decision preparation failed: " + err.Error() + ": " + string(output))
		}
		return nil
	}
	identity := setupIdentity{ID: marker.Binding.IdentityID}
	common := []string{"--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/setup-coordinator.hex"}
	decisionHost := filepath.Join(public, "decision", "decision.json")
	for _, path := range []string{workflowV4QuestionnairePath(work), filepath.Join(work, "workflow-v4", "decision"), filepath.Join(work, "decision-draft.json")} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	_, policySHA, err := workflowV4DecisionDefinition(protocol, work)
	if err != nil {
		t.Fatal(err)
	}
	candidateID, err := workflowV4CandidateID(snapshot, work)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := workflowV4AcceptedReviewScopes(snapshot, protocol)
	if err != nil {
		t.Fatal(err)
	}
	answers := workflowV4DecisionAnswers{Schema: workflowV4DecisionQuestionsSchema, CeremonyID: definition.CeremonyID, CandidateID: candidateID, CheckpointSHA256: snapshot.Head().Record.Digest.SHA256, PolicySHA256: policySHA, CoordinatorID: identity.ID, Accepted: accepted, Answers: map[string]string{}}
	for _, question := range workflowV4DecisionQuestionsV2(answers) {
		answers.Answers[question.key] = question.fallback
	}
	answers.Answers["final.withhold"] = "No"
	answers.Answers["final.findings"] = "Not assessed"
	if err := saveJSONAtomic(workflowV4QuestionnairePath(work), answers); err != nil {
		t.Fatal(err)
	}
	var screen bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("PREPARE NO-GO\n")), output: &screen}
	if err := runWorkflowV4GuidedDecision(ui, onlineProfile, signerProfile, identity, protocol, snapshot, common, decisionHost, public); err != nil {
		t.Fatalf("prepare fixture's first unsigned decision: %v\n%s", err, screen.String())
	}
	if proofCalls != 1 {
		t.Fatalf("initial guided decision called proof-tool %d times, want 1", proofCalls)
	}
	var replacementScreen bytes.Buffer
	replacementUI := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("8\nREPLACE UNSIGNED DECISION\nNOT CIRCULATED\nCorrect synthetic review answers\n")), output: &replacementScreen}
	if err := runWorkflowV4DecisionMenu(replacementUI, onlineProfile, signerProfile, identity, protocol, &snapshot); err != nil {
		t.Fatalf("retire old unsigned decision: %v\n%s", err, replacementScreen.String())
	}
	if proofCalls != 1 {
		t.Fatalf("retirement reran pinned proof-tool on old decision: %d calls", proofCalls)
	}
	if state, err := decisionReplacementReadState(work); err != nil || len(state.Committed) != 1 || !state.Awaiting {
		t.Fatalf("old decision was not retained privately: %+v, %v", state, err)
	}
	t.Log("initial D → 8 authenticated the real signed checkpoint and retired the exact old unsigned decision without rerunning proof-tool")
	replacement, err := decisionReplacementReadState(work)
	if err != nil {
		t.Fatal(err)
	}
	latest, ok := decisionReplacementLatest(replacement)
	if !ok {
		t.Fatal("committed old decision is missing")
	}
	if err := decisionReplacementSeedQuestionnaire(work, latest); err != nil {
		t.Fatal(err)
	}
	var corrected workflowV4DecisionAnswers
	if err := setupReadJSON(workflowV4QuestionnairePath(work), &corrected); err != nil {
		t.Fatal(err)
	}
	corrected.Answers["final.withhold"] = "Yes"
	corrected.Answers["final.findings"] = "Test-only review remains incomplete; withhold GO"
	if err := saveJSONAtomic(workflowV4QuestionnairePath(work), corrected); err != nil {
		t.Fatal(err)
	}
	failNextPreparation = true
	var failedScreen bytes.Buffer
	failedUI := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("1\nPREPARE NO-GO\n")), output: &failedScreen}
	if err := runWorkflowV4DecisionMenu(failedUI, onlineProfile, signerProfile, identity, protocol, &snapshot); err == nil || !strings.Contains(err.Error(), "test-only pinned preparation failure") {
		t.Fatalf("new decision ignored pinned preparation failure: %v\n%s", err, failedScreen.String())
	}
	if _, err := os.Stat(decisionHost); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed pinned preparation promoted a new decision")
	}
	var retryScreen bytes.Buffer
	retryUI := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("1\n")), output: &retryScreen}
	if err := runWorkflowV4DecisionMenu(retryUI, onlineProfile, signerProfile, identity, protocol, &snapshot); err != nil {
		t.Fatalf("new decision did not recover and pass pinned preparation: %v\n%s", err, retryScreen.String())
	}
	newBytes, err := os.ReadFile(decisionHost)
	if err != nil || decisionReplacementDigest(newBytes) == latest.OldDecisionSHA256 {
		t.Fatalf("replacement decision is absent or unchanged: %v", err)
	}
	if proofCalls != 3 {
		t.Fatalf("expected first preparation, failed replacement preparation, and successful retry; got %d calls", proofCalls)
	}
	t.Log("D → 1 withheld the new decision after a pinned failure, then prepared a different decision on exact retry")
	var refusalScreen bytes.Buffer
	refusalUI := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("8\n")), output: &refusalScreen}
	evidence := filepath.Join(public, "decision", "evidence", "formal-go-no-go-checklist.md")
	evidenceRaw, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidence, append(append([]byte{}, evidenceRaw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runWorkflowV4DecisionMenu(refusalUI, onlineProfile, signerProfile, identity, protocol, &snapshot); err == nil {
		t.Fatal("D → 8 accepted altered decision evidence")
	}
	if err := os.WriteFile(evidence, evidenceRaw, 0600); err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(public, "decision", "coordinator.sig")
	if err := os.WriteFile(signature, []byte("test-only signing marker"), 0600); err != nil {
		t.Fatal(err)
	}
	refusalScreen.Reset()
	refusalUI = &coordinatorWizard{input: bufio.NewReader(strings.NewReader("8\n")), output: &refusalScreen}
	if err := runWorkflowV4DecisionMenu(refusalUI, onlineProfile, signerProfile, identity, protocol, &snapshot); err == nil {
		t.Fatal("D → 8 accepted a decision with signing started")
	}
	if err := os.Remove(signature); err != nil {
		t.Fatal(err)
	}
	if proofCalls != 3 {
		t.Fatal("refusal checks unexpectedly reran pinned proof-tool")
	}
	t.Log("D → 8 refused altered evidence and a local signing marker")
}
