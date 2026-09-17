package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func commitDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func testCoordinatorCommitPlan(root string) coordinatorCommitPlan {
	ceremonyID := commitDigest("1")
	previousRoot := state.Root{
		Schema: state.RootSchema, CeremonyID: ceremonyID,
		Checkpoint:          state.ContentRef{Name: "checkpoints/0000.json", SHA256: commitDigest("2"), Size: 100},
		CheckpointSignature: state.ContentRef{Name: "checkpoints/0000.sig", SHA256: commitDigest("3"), Size: 64},
	}
	previousVersion := store.ObjectVersion{ETag: `"parent-etag"`, VersionID: "parent-version", Size: 512}
	return coordinatorCommitPlan{
		OperationID: strings.Repeat("1", 32), CeremonyID: ceremonyID,
		PreviousRoot: &previousRoot, PreviousRootVersion: &previousVersion,
		InnerOutputPaths: []string{filepath.Join(root, "chain.json"), filepath.Join(root, "chain.sig")},
	}
}

func testCheckpointIntent(root string) coordinatorCheckpointSigningIntent {
	return coordinatorCheckpointSigningIntent{
		CheckpointOutputPath:          filepath.Join(root, "checkpoint.json"),
		CheckpointSignatureOutputPath: filepath.Join(root, "checkpoint.sig"),
		TargetCheckpointPath:          store.Key(commitDigest("5")),
		TargetCheckpointSignaturePath: store.Key(commitDigest("6")),
	}
}

func testAuthenticatedChild(root string, plan coordinatorCommitPlan) coordinatorAuthenticatedChild {
	return coordinatorAuthenticatedChild{
		ArtifactRoot:        root,
		Checkpoint:          state.ContentRef{Name: "checkpoints/0001.json", SHA256: commitDigest("5"), Size: 200},
		CheckpointSignature: state.ContentRef{Name: "checkpoints/0001.sig", SHA256: commitDigest("6"), Size: 64},
		Evidence: coordinatorAuthenticatedChildEvidence{
			CeremonyID: plan.CeremonyID, Sequence: 1, CheckpointDigest: commitDigest("5"),
			TransitionKind: "phase1-outbound-published", FullyVerified: true,
		},
	}
}

func committedRootVersion() store.ObjectVersion {
	return store.ObjectVersion{ETag: `"committed-etag"`, VersionID: "committed-version", Size: 512}
}

func testRootIntent(root string) coordinatorRootCASIntent {
	return coordinatorRootCASIntent{
		RootPayloadOutputPath: filepath.Join(root, "root.json"),
		TargetRootPath:        state.RootKey(commitDigest("1")),
	}
}

func commitOutput(path, c string) coordinatorCommitOutput {
	return coordinatorCommitOutput{Path: path, SHA256: commitDigest(c)}
}

func openTestCommitJournal(t *testing.T) (*coordinatorCommitJournal, coordinatorCommitPlan) {
	t.Helper()
	root := t.TempDir()
	plan := testCoordinatorCommitPlan(root)
	journal, err := openOrCreateCoordinatorCommitJournal(filepath.Join(root, "journal", "commit.json"), plan)
	if err != nil {
		t.Fatal(err)
	}
	return journal, plan
}

func TestCoordinatorCommitJournalPersistsEveryIntentBoundary(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	rootIntent := testRootIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	assertCommitJournalStage(t, journal.path, commitInnerSigningIntent)

	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[1], "4"), commitOutput(plan.InnerOutputPaths[0], "3")}
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitInnerSigned)
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitCheckpointSigningIntent)
	checkpoint := commitOutput(checkpointIntent.CheckpointOutputPath, "5")
	signature := commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")
	if err := journal.recordCheckpointSigned(checkpoint, signature); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitCheckpointSigned)
	if err := journal.recordAuthenticatedChild(testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitChildAuthenticated)
	rootPayload := commitOutput(rootIntent.RootPayloadOutputPath, "7")
	if err := journal.rootCASIntent(rootIntent, rootPayload); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitRootCASIntent)
	if err := journal.recordRootCASCommitted(committedRootVersion()); err != nil {
		t.Fatal(err)
	}
	assertCommitJournalStage(t, journal.path, commitRootCASCommitted)

	reopened, err := openOrCreateCoordinatorCommitJournal(journal.path, plan)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.stage() != commitRootCASCommitted || reopened.record.Plan.PreviousRootVersion == nil || reopened.record.Plan.PreviousRootVersion.VersionID != "parent-version" || reopened.record.AuthenticatedChild == nil || reopened.record.RootIntent == nil || reopened.record.RootIntent.TargetRootPath != state.RootKey(plan.CeremonyID) {
		t.Fatalf("reopened journal lost exact commit state: %+v", reopened.record)
	}
	info, err := os.Stat(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %o", info.Mode().Perm())
	}
}

func TestCoordinatorCommitJournalReloadsExactStateAtEveryCrashBoundary(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	rootIntent := testRootIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}
	checkpoint := commitOutput(checkpointIntent.CheckpointOutputPath, "5")
	signature := commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")
	child := testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)
	rootPayload := commitOutput(rootIntent.RootPayloadOutputPath, "7")
	committed := committedRootVersion()

	reopen := func(want coordinatorCommitStage) {
		t.Helper()
		var err error
		journal, err = openOrCreateCoordinatorCommitJournal(journal.path, plan)
		if err != nil {
			t.Fatal(err)
		}
		if journal.stage() != want {
			t.Fatalf("reloaded stage = %q, want %q", journal.stage(), want)
		}
		if journal.record.Plan.PreviousRoot == nil || journal.record.Plan.PreviousRootVersion == nil ||
			journal.record.Plan.PreviousRoot.Checkpoint.SHA256 != commitDigest("2") ||
			journal.record.Plan.PreviousRootVersion.VersionID != "parent-version" {
			t.Fatalf("reloaded journal lost exact prior root: %+v", journal.record.Plan)
		}
	}

	reopen(commitInnerSigningIntent)
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	reopen(commitInnerSigned)
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	reopen(commitCheckpointSigningIntent)
	if err := journal.recordCheckpointSigned(checkpoint, signature); err != nil {
		t.Fatal(err)
	}
	reopen(commitCheckpointSigned)
	if err := journal.recordAuthenticatedChild(child); err != nil {
		t.Fatal(err)
	}
	reopen(commitChildAuthenticated)
	if journal.record.AuthenticatedChild.Checkpoint != child.Checkpoint || journal.record.AuthenticatedChild.Evidence != child.Evidence {
		t.Fatal("reloaded journal lost authenticated child inputs")
	}
	if err := journal.rootCASIntent(rootIntent, rootPayload); err != nil {
		t.Fatal(err)
	}
	reopen(commitRootCASIntent)
	if err := journal.recordRootCASCommitted(committed); err != nil {
		t.Fatal(err)
	}
	reopen(commitRootCASCommitted)
	if journal.record.CommittedRootVersion == nil || *journal.record.CommittedRootVersion != committed {
		t.Fatal("reloaded journal lost committed root version")
	}
}

func TestCoordinatorCommitJournalRequiresStrictForwardTransitions(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	rootIntent := testRootIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	checkpoint := commitOutput(checkpointIntent.CheckpointOutputPath, "5")
	signature := commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")
	rootPayload := commitOutput(rootIntent.RootPayloadOutputPath, "7")

	if err := journal.checkpointSigningIntent(checkpointIntent); err == nil {
		t.Fatal("checkpoint intent skipped inner signing completion")
	}
	if err := journal.recordCheckpointSigned(checkpoint, signature); err == nil {
		t.Fatal("checkpoint completion skipped its intent")
	}
	if err := journal.rootCASIntent(rootIntent, rootPayload); err == nil {
		t.Fatal("root CAS intent skipped signed checkpoint")
	}
	if err := journal.recordAuthenticatedChild(testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)); err == nil {
		t.Fatal("child authentication skipped checkpoint completion")
	}
	if err := journal.recordRootCASCommitted(committedRootVersion()); err == nil {
		t.Fatal("root CAS completion skipped its intent")
	}
	assertCommitJournalStage(t, journal.path, commitInnerSigningIntent)
}

func TestCoordinatorCommitJournalRootIntentUsesExactCeremonyRootKey(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	if err := journal.recordInnerSigned([]coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}); err != nil {
		t.Fatal(err)
	}
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordCheckpointSigned(commitOutput(checkpointIntent.CheckpointOutputPath, "5"), commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordAuthenticatedChild(testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)); err != nil {
		t.Fatal(err)
	}
	wrong := testRootIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	wrong.TargetRootPath = state.RootKey(commitDigest("9"))
	if err := journal.rootCASIntent(wrong, commitOutput(wrong.RootPayloadOutputPath, "7")); err == nil {
		t.Fatal("root intent for another ceremony key was accepted")
	}
	if journal.stage() != commitChildAuthenticated {
		t.Fatalf("failed root intent advanced journal to %q", journal.stage())
	}
}

func TestCoordinatorCommitJournalResumeMustMatchExactly(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordInnerSigned([]coordinatorCommitOutput{inner[0], commitOutput(plan.InnerOutputPaths[1], "9")}); err == nil {
		t.Fatal("changed inner output digest was accepted on resume")
	}
	if err := journal.recordInnerSigned([]coordinatorCommitOutput{inner[1], inner[0]}); err != nil {
		t.Fatalf("equivalent reordered outputs should resume: %v", err)
	}
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	changedCheckpointIntent := checkpointIntent
	changedCheckpointIntent.TargetCheckpointPath = "checkpoints/other.json"
	if err := journal.checkpointSigningIntent(changedCheckpointIntent); err == nil {
		t.Fatal("resume with another checkpoint target was accepted")
	}

	changed := cloneCoordinatorCommitPlan(plan)
	changed.PreviousRootVersion.ETag = `"another-etag"`
	if _, err := openOrCreateCoordinatorCommitJournal(journal.path, changed); err == nil {
		t.Fatal("resume with another parent root ETag was accepted")
	}
	changed = plan
	changed.InnerOutputPaths = append([]string(nil), plan.InnerOutputPaths...)
	changed.InnerOutputPaths[0] = filepath.Join(filepath.Dir(plan.InnerOutputPaths[0]), "other-chain.json")
	if _, err := openOrCreateCoordinatorCommitJournal(journal.path, changed); err == nil {
		t.Fatal("resume with another output plan was accepted")
	}
}

func TestCoordinatorCommitJournalCopiesPlanAndRejectsOverlappingLaterPaths(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	original := journal.record.Plan.InnerOutputPaths[0]
	plan.InnerOutputPaths[0] = filepath.Join(filepath.Dir(original), "mutated.json")
	plan.PreviousRoot.Checkpoint.SHA256 = commitDigest("9")
	plan.PreviousRootVersion.VersionID = "mutated-version"
	if journal.record.Plan.InnerOutputPaths[0] != original {
		t.Fatal("caller mutation changed the durable journal plan")
	}
	if journal.record.Plan.PreviousRoot.Checkpoint.SHA256 != commitDigest("2") || journal.record.Plan.PreviousRootVersion.VersionID != "parent-version" {
		t.Fatal("caller mutation changed the durable prior root plan")
	}
	inner := []coordinatorCommitOutput{commitOutput(journal.record.Plan.InnerOutputPaths[0], "3"), commitOutput(journal.record.Plan.InnerOutputPaths[1], "4")}
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	checkpointIntent := testCheckpointIntent(filepath.Dir(original))
	checkpointIntent.CheckpointOutputPath = original
	if err := journal.checkpointSigningIntent(checkpointIntent); err == nil {
		t.Fatal("checkpoint intent reused an inner output path")
	}
}

func TestCoordinatorCommitJournalAuthenticatedChildMustMatchExactOutputsAndEvidence(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordCheckpointSigned(commitOutput(checkpointIntent.CheckpointOutputPath, "5"), commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")); err != nil {
		t.Fatal(err)
	}
	valid := testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)
	cases := map[string]func(*coordinatorAuthenticatedChild){
		"artifact root":      func(c *coordinatorAuthenticatedChild) { c.ArtifactRoot = "relative" },
		"checkpoint digest":  func(c *coordinatorAuthenticatedChild) { c.Checkpoint.SHA256 = commitDigest("9") },
		"signature digest":   func(c *coordinatorAuthenticatedChild) { c.CheckpointSignature.SHA256 = commitDigest("9") },
		"evidence ceremony":  func(c *coordinatorAuthenticatedChild) { c.Evidence.CeremonyID = commitDigest("9") },
		"evidence digest":    func(c *coordinatorAuthenticatedChild) { c.Evidence.CheckpointDigest = commitDigest("9") },
		"not fully verified": func(c *coordinatorAuthenticatedChild) { c.Evidence.FullyVerified = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := journal.recordAuthenticatedChild(candidate); err == nil {
				t.Fatal("mismatched authenticated child accepted")
			}
		})
	}
	if journal.stage() != commitCheckpointSigned {
		t.Fatalf("failed child validation advanced journal to %q", journal.stage())
	}
}

func TestCoordinatorCommitJournalSupportsExactInitialRootPlan(t *testing.T) {
	root := t.TempDir()
	plan := testCoordinatorCommitPlan(root)
	plan.PreviousRoot = nil
	plan.PreviousRootVersion = nil
	journal, err := openOrCreateCoordinatorCommitJournal(filepath.Join(root, "journal.json"), plan)
	if err != nil {
		t.Fatal(err)
	}
	checkpointIntent := testCheckpointIntent(root)
	if err := journal.recordInnerSigned([]coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}); err != nil {
		t.Fatal(err)
	}
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordCheckpointSigned(commitOutput(checkpointIntent.CheckpointOutputPath, "5"), commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")); err != nil {
		t.Fatal(err)
	}
	child := testAuthenticatedChild(root, plan)
	child.Evidence.Sequence = 0
	if err := journal.recordAuthenticatedChild(child); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorCommitJournalDoesNotAdvanceMemoryWhenDurableWriteFails(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	journalDir := filepath.Dir(journal.path)
	movedDir := journalDir + "-moved"
	if err := os.Rename(journalDir, movedDir); err != nil {
		t.Fatal(err)
	}
	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}
	if err := journal.recordInnerSigned(inner); err == nil {
		t.Fatal("journal claimed success when its directory was unavailable")
	}
	if journal.stage() != commitInnerSigningIntent {
		t.Fatalf("in-memory stage advanced after failed durable write: %s", journal.stage())
	}
	record, exists, err := readCoordinatorCommitJournal(filepath.Join(movedDir, filepath.Base(journal.path)))
	if err != nil || !exists || record.Stage != commitInnerSigningIntent {
		t.Fatalf("durable stage changed after failed write: %+v exists=%v err=%v", record, exists, err)
	}
}

func TestCoordinatorCommitJournalRejectsConflictingCompletedResume(t *testing.T) {
	journal, plan := openTestCommitJournal(t)
	checkpointIntent := testCheckpointIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	rootIntent := testRootIntent(filepath.Dir(plan.InnerOutputPaths[0]))
	inner := []coordinatorCommitOutput{commitOutput(plan.InnerOutputPaths[0], "3"), commitOutput(plan.InnerOutputPaths[1], "4")}
	if err := journal.recordInnerSigned(inner); err != nil {
		t.Fatal(err)
	}
	if err := journal.checkpointSigningIntent(checkpointIntent); err != nil {
		t.Fatal(err)
	}
	checkpoint := commitOutput(checkpointIntent.CheckpointOutputPath, "5")
	signature := commitOutput(checkpointIntent.CheckpointSignatureOutputPath, "6")
	if err := journal.recordCheckpointSigned(checkpoint, signature); err != nil {
		t.Fatal(err)
	}
	if err := journal.recordCheckpointSigned(commitOutput(checkpointIntent.CheckpointOutputPath, "9"), signature); err == nil {
		t.Fatal("changed checkpoint digest was accepted on resume")
	}
	child := testAuthenticatedChild(filepath.Dir(plan.InnerOutputPaths[0]), plan)
	if err := journal.recordAuthenticatedChild(child); err != nil {
		t.Fatal(err)
	}
	changedChild := child
	changedChild.Evidence.TransitionKind = "phase1-receipt-accepted"
	if err := journal.recordAuthenticatedChild(changedChild); err == nil {
		t.Fatal("changed authenticated child evidence was accepted on resume")
	}
	rootPayload := commitOutput(rootIntent.RootPayloadOutputPath, "7")
	if err := journal.rootCASIntent(rootIntent, rootPayload); err != nil {
		t.Fatal(err)
	}
	if err := journal.rootCASIntent(rootIntent, commitOutput(rootIntent.RootPayloadOutputPath, "8")); err == nil {
		t.Fatal("changed root payload was accepted on resume")
	}
	committed := committedRootVersion()
	if err := journal.recordRootCASCommitted(committed); err != nil {
		t.Fatal(err)
	}
	changedCommitted := committed
	changedCommitted.VersionID = "different-version"
	if err := journal.recordRootCASCommitted(changedCommitted); err == nil {
		t.Fatal("changed committed object version was accepted on resume")
	}
}

func TestCoordinatorCommitJournalRejectsMalformedPlanAndRecord(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "journal.json")
	plan := testCoordinatorCommitPlan(root)
	cases := map[string]func(*coordinatorCommitPlan){
		"operation":        func(p *coordinatorCommitPlan) { p.OperationID = "short" },
		"ceremony":         func(p *coordinatorCommitPlan) { p.CeremonyID = "sha256:BAD" },
		"parent ceremony":  func(p *coordinatorCommitPlan) { p.PreviousRoot.CeremonyID = commitDigest("9") },
		"parent etag":      func(p *coordinatorCommitPlan) { p.PreviousRootVersion.ETag = "bad\nvalue" },
		"local output":     func(p *coordinatorCommitPlan) { p.InnerOutputPaths[0] = "relative.json" },
		"duplicate output": func(p *coordinatorCommitPlan) { p.InnerOutputPaths[1] = p.InnerOutputPaths[0] },
		"missing root":     func(p *coordinatorCommitPlan) { p.PreviousRoot = nil },
		"missing version":  func(p *coordinatorCommitPlan) { p.PreviousRootVersion = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCoordinatorCommitPlan(plan)
			mutate(&candidate)
			if _, err := openOrCreateCoordinatorCommitJournal(path, candidate); err == nil {
				t.Fatal("malformed commit plan accepted")
			}
		})
	}

	journal, err := openOrCreateCoordinatorCommitJournal(path, plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["unknown"] = true
	raw, _ = json.Marshal(generic)
	if err := os.WriteFile(journal.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCoordinatorCommitJournal(journal.path); err == nil {
		t.Fatal("unknown journal field accepted")
	}
}

func assertCommitJournalStage(t *testing.T, path string, want coordinatorCommitStage) {
	t.Helper()
	record, exists, err := readCoordinatorCommitJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || record.Stage != want {
		t.Fatalf("journal stage = %q, exists=%v, want %q", record.Stage, exists, want)
	}
}
