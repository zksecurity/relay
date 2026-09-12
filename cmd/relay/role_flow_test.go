package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestRoleFlowChildForwardsTerminationAndWaitsForCleanup(t *testing.T) {
	const variable = "RELAY_FLOW_SIGNAL_TEST"
	const testName = "^TestRoleFlowChildForwardsTerminationAndWaitsForCleanup$"
	switch os.Getenv(variable) {
	case "child":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		// Only this test's intermediate parent receives the signal. It must
		// forward it here, wait for cleanup, and then return normally.
		if err := syscall.Kill(os.Getppid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-signals:
			if err := os.WriteFile(os.Getenv("RELAY_FLOW_SIGNAL_OUTPUT"), []byte("cleanup complete"), 0600); err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("parent did not forward termination")
		}
		return
	case "parent":
		t.Setenv(variable, "child")
		if err := executeGuidedChild([]string{"-test.run=" + testName}); err != nil {
			t.Fatal(err)
		}
		if raw, err := os.ReadFile(os.Getenv("RELAY_FLOW_SIGNAL_OUTPUT")); err != nil || string(raw) != "cleanup complete" {
			t.Fatalf("launcher returned before child cleanup: %v", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run="+testName)
	command.Env = append(os.Environ(), variable+"=parent", "RELAY_FLOW_SIGNAL_OUTPUT="+filepath.Join(t.TempDir(), "cleanup.txt"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("signal-forwarding helper: %v\n%s", err, output)
	}
}

func flowFixture(t *testing.T) *roleFlow {
	t.Helper()
	root := t.TempDir()
	task := withFields(flowProof("verify", "Verify definition", "Read-only", "inspect", "definition"))
	return &roleFlow{state: roleFlowState{Schema: roleFlowSchema, Name: "test", Role: "coordinator", Values: map[string]string{}}, stages: []flowStage{{ID: "test", Label: "Test", Tasks: []flowTask{task}}}, path: filepath.Join(root, "state.json"), ui: coordinatorWizard{input: bufio.NewReader(strings.NewReader("")), output: new(bytes.Buffer)}, run: func(flowTask, []string, string, bool) error { return nil }}
}

func TestFlowWorkspaceInitializationAndLossDetection(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	workflow := filepath.Join(root, "workflow")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workflow, 0o700); err != nil {
		t.Fatal(err)
	}
	p := guidedProfile{Name: "demo", Role: "participant", Work: work}
	state := roleFlowState{Schema: roleFlowSchema, Name: p.Name, Role: p.Role, Values: map[string]string{}}
	statePath := filepath.Join(workflow, "state.json")
	if err := ensureFlowWorkspace(statePath, p, &state, false); err != nil {
		t.Fatal(err)
	}
	if state.WorkspaceID == "" || state.WorkspaceStatus != "ready" {
		t.Fatalf("workspace was not made ready: %#v", state)
	}
	var marker flowWorkspaceMarker
	if err := setupReadJSON(filepath.Join(work, flowWorkspaceFileName), &marker); err != nil {
		t.Fatal(err)
	}
	if marker.WorkspaceID != state.WorkspaceID {
		t.Fatal("workspace marker and state differ")
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	fresh := roleFlowState{Schema: roleFlowSchema, Name: p.Name, Role: p.Role, Values: map[string]string{}}
	if err := ensureFlowWorkspace(statePath, p, &fresh, false); err == nil || !strings.Contains(err.Error(), "state is missing") {
		t.Fatalf("deleted recovery state looked like first use: %v", err)
	}
}

func TestFlowCatalogMigrationUsesStableStageID(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	oldDigest := "sha256:" + strings.Repeat("a", 64)
	newDigest := "sha256:" + strings.Repeat("b", 64)
	state := roleFlowState{
		Schema: roleFlowSchema, CatalogDigest: oldDigest, Stage: 0, StageID: "second",
		ViewHistory: []int{0}, Values: map[string]string{},
		Attempts: []flowAttempt{{ID: "old-operation", Task: "task", Stage: "second", Status: "running", Command: []string{"status"}}},
	}
	if err := writeJSONNoReplace(path, state, 0o600); err != nil {
		t.Fatal(err)
	}
	stages := []flowStage{{ID: "new-first"}, {ID: "second"}}
	if err := migrateFlowCatalog(path, newDigest, stages, &state); err != nil {
		t.Fatal(err)
	}
	if state.Stage != 1 || state.StageID != "second" || state.CatalogDigest != newDigest || len(state.ViewHistory) != 0 {
		t.Fatalf("migrated state = %#v", state)
	}
	if len(state.Attempts) != 1 || state.Attempts[0].ID != "old-operation" {
		t.Fatal("catalog migration discarded the unresolved operation")
	}
	if _, err := os.Lstat(path + ".pre-catalog-" + strings.Repeat("a", 12) + ".bak"); err != nil {
		t.Fatal("catalog migration did not retain its source state:", err)
	}
}

func TestFlowCatalogMigrationBlocksLegacyStateWithoutStageID(t *testing.T) {
	state := roleFlowState{Schema: roleFlowSchemaV1, CatalogDigest: "sha256:" + strings.Repeat("a", 64), Stage: 0}
	err := migrateFlowCatalog(filepath.Join(t.TempDir(), "state.json"), "sha256:"+strings.Repeat("b", 64), []flowStage{{ID: "first"}}, &state)
	if err == nil || !strings.Contains(err.Error(), "without a stable stage ID") {
		t.Fatalf("legacy catalog mismatch error = %v", err)
	}
}

func TestFlowWorkspaceResumesInitializationAndMigratesV1(t *testing.T) {
	for _, test := range []struct {
		name, schema, status string
		legacy               bool
	}{{"initializing", roleFlowSchema, "initializing", false}, {"legacy", roleFlowSchemaV1, "", true}} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			work, workflow := filepath.Join(root, "work"), filepath.Join(root, "workflow")
			if err := os.MkdirAll(work, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(workflow, 0o700); err != nil {
				t.Fatal(err)
			}
			p := guidedProfile{Name: "demo", Role: "auditor", Work: work}
			state := roleFlowState{Schema: test.schema, Name: p.Name, Role: p.Role, Values: map[string]string{}, WorkspaceStatus: test.status}
			if !test.legacy {
				state.WorkspaceID = "fixed-workspace"
			}
			statePath := filepath.Join(workflow, "state.json")
			if err := writeJSONNoReplace(statePath, state, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ensureFlowWorkspace(statePath, p, &state, true); err != nil {
				t.Fatal(err)
			}
			if state.Schema != roleFlowSchema || state.WorkspaceID == "" || state.WorkspaceStatus != "ready" {
				t.Fatalf("workspace did not recover: %#v", state)
			}
			if test.legacy {
				if _, err := os.Stat(statePath + ".pre-recovery-v2.bak"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestNormalizeSavedParticipantProfileOnlyFillsLegacyOmissions(t *testing.T) {
	current := guidedProfile{Schema: guidedSchema, Name: "demo", Role: "participant", ReleaseCommit: strings.Repeat("a", 40), Config: "/tmp/participant.json", Work: "/tmp/work", Trust: "/tmp/trust", Keys: "/tmp/keys", Image: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"}
	legacy := current
	legacy.Work, legacy.Trust, legacy.Keys, legacy.Image, legacy.Platform = "", "", "", "", ""
	if !normalizeSavedParticipantProfile(&legacy, current) || !reflect.DeepEqual(legacy, current) {
		t.Fatal("safe legacy omissions were not normalized")
	}
	changed := current
	changed.Image = "sha256:" + strings.Repeat("c", 64)
	if normalizeSavedParticipantProfile(&changed, current) {
		t.Fatal("conflicting participant runtime was normalized")
	}
}

func TestRoleFlowDoesNotHideUnresolvedOlderTurn(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	oldScope := &flowTurnScope{Phase: "phase1", Participant: "first", Head: "head-0"}
	currentScope := &flowTurnScope{Phase: "phase1", Participant: "second", Head: "head-1"}
	f.state.Attempts = []flowAttempt{{ID: "old", Task: task.ID, Stage: "test", Status: "running", TurnScope: oldScope}, {ID: "new", Task: task.ID, Stage: "test", Status: "succeeded", TurnScope: currentScope}}
	f.turnScope = currentScope
	if got := f.last(task); got == nil || got.ID != "old" {
		t.Fatalf("older uncertain operation was hidden: %#v", got)
	}
}

func TestRoleFlowEveryRoleHasDistinctStagesAndSafeRecipes(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		stages := roleFlowStages(role)
		if len(stages) < 2 {
			t.Fatalf("missing flow for %s", role)
		}
		seenStages := map[string]bool{}
		for _, stage := range stages {
			if seenStages[stage.ID] {
				t.Fatal("duplicate stage", role, stage.ID)
			}
			seenStages[stage.ID] = true
			seenTasks := map[string]bool{}
			for _, task := range stage.Tasks {
				if seenTasks[task.ID] {
					t.Fatal("duplicate task", role, stage.ID, task.ID)
				}
				seenTasks[task.ID] = true
				if task.Label == "" || task.Help == "" {
					t.Fatal("missing human explanation")
				}
				if flowTaskRecoveryClass(task) == recoveryUnclassified {
					t.Fatal("missing recovery classification", role, stage.ID, task.ID, task.Command)
				}
				if task.Handoff {
					if len(task.Command) != 0 {
						t.Fatal("handoff has command")
					}
					continue
				}
				command := append([]string(nil), task.Command...)
				for _, field := range task.Fields {
					value := field.Default
					if value == "NOW" {
						value = "2026-09-08T12:00:00Z"
					}
					if value == "" {
						if field.Optional {
							continue
						}
						switch field.Kind {
						case "path":
							value = "/work/input.json"
						case "host":
							value = "/tmp/role/input.json"
						case "number":
							value = "1"
						case "time":
							value = "2026-09-08T12:00:00Z"
						default:
							value = "example"
						}
					}
					command = append(command, "--"+field.Flag, value)
				}
				if err := validateFlowCommand(task, command); err != nil {
					t.Fatalf("%s/%s/%s: %v", role, stage.ID, task.ID, err)
				}
				if role == "participant" && task.Offline {
					if len(command) < 3 || command[0] != "mpc-ceremony" || command[1] != "ops" || (command[2] != "prepare-handoff" && command[2] != "prepare-receipt" && command[2] != "sign" && command[2] != "verify") {
						t.Fatal("participant offline action is not a custody operation")
					}
				} else if role == "participant" {
					if command[0] != "run" && command[0] != "status" {
						t.Fatal("participant bypasses supervisor")
					}
				} else {
					if command[0] != "relay" && command[0] != "mpc-ceremony" {
						t.Fatal("unknown executable")
					}
					if role == "release-signer" && command[0] != "mpc-ceremony" {
						t.Fatal("offline signer uses online command")
					}
				}
			}
		}
	}
}

func TestCustodyDirectionIsFixedByWorkflow(t *testing.T) {
	f := flowFixture(t)
	task := flowTask{ID: "prepare-outbound-handoff", Command: []string{"mpc-ceremony", "ops", "prepare-handoff"}, Fields: []flowField{ft("direction", "Handoff direction", "outbound")}}
	command, err := f.command(task)
	if err != nil {
		t.Fatal(err)
	}
	if got := commandValue(command, "direction"); got != "outbound" {
		t.Fatalf("workflow allowed an editable direction: %q (%q)", got, command)
	}
	invalid := append([]string(nil), command...)
	invalid[len(invalid)-1] = "1"
	if err := validateFlowCommand(task, invalid); err == nil {
		t.Fatal("obsolete editable custody direction was accepted for retry")
	}
	if !strings.Contains(f.ui.output.(*bytes.Buffer).String(), "Handoff direction: outbound (fixed by workflow)") {
		t.Fatal("fixed direction was not shown for review")
	}
}

func TestRoleFlowConsentJournalAndResume(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	calls := 0
	f.run = func(_ flowTask, command []string, _ string, retry bool) error {
		calls++
		var saved roleFlowState
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if saved.Attempts[len(saved.Attempts)-1].Status != "running" {
			t.Fatal("execution started without durable running record")
		}
		attempt := saved.Attempts[len(saved.Attempts)-1]
		if attempt.OperationSchema != flowOperationSchema || attempt.RecoveryClass != recoveryReadOnly {
			t.Fatalf("operation was not classified before execution: %#v", attempt)
		}
		if calls == 1 {
			return errors.New("interrupted")
		}
		if !retry {
			t.Fatal("retry was not explicit")
		}
		return nil
	}
	f.ui.input = bufio.NewReader(strings.NewReader("\n\n\nno\n"))
	if err := f.execute(task); err == nil || calls != 0 || len(f.state.Attempts) != 0 {
		t.Fatal("ran without consent")
	}
	f.ui.input = bufio.NewReader(strings.NewReader("\n\n\nRUN\n"))
	if err := f.execute(task); err == nil || f.last(task).Status != "failed" {
		t.Fatal("failed command recorded as success")
	}
	if err := f.advance(); err == nil {
		t.Fatal("advanced past failure")
	}
	f.ui.input = bufio.NewReader(strings.NewReader("RUN\n"))
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || f.last(task).Status != "succeeded" {
		t.Fatal("retry not recorded")
	}
	if f.state.Attempts[0].ID != f.state.Attempts[1].ID {
		t.Fatal("retry changed underlying action")
	}
	info, err := os.Stat(f.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe state permissions")
	}
	f.ui.input = bufio.NewReader(strings.NewReader("CONTINUE\n"))
	if err := f.advance(); err != nil {
		t.Fatal(err)
	}
	if f.state.Stage != 1 {
		t.Fatal("did not advance")
	}
}

func TestRoleFlowPreparedAttemptReturnsToNormalReview(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	command := append([]string(nil), task.Command...)
	for _, field := range task.Fields {
		command = append(command, "--"+field.Flag, field.Default)
	}
	f.state.Attempts = []flowAttempt{{
		ID: "flow-" + strings.Repeat("c", 32), Task: task.ID, Stage: "test",
		Status: "prepared", OperationSchema: flowOperationSchema,
		RecoveryClass: recoveryReadOnly, Command: command,
	}}
	f.ui.input = bufio.NewReader(strings.NewReader("\n\n\nRUN\n"))
	calls := 0
	f.run = func(flowTask, []string, string, bool) error { calls++; return nil }
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(f.state.Attempts) != 2 || f.state.Attempts[0].Status != "not-started" || f.state.Attempts[1].Status != "succeeded" {
		t.Fatalf("prepared recovery = calls %d, attempts %#v", calls, f.state.Attempts)
	}
	if !strings.Contains(f.ui.output.(*bytes.Buffer).String(), "no command ran") {
		t.Fatal("prepared recovery did not explain the safe restart")
	}
}

func TestRoleFlowRejectsTamperedRetry(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{ID: "test", Task: task.ID, Stage: "test", Status: "running", Command: []string{"mpc-ceremony", "phase1", "contribute"}}}
	f.ui.input = bufio.NewReader(strings.NewReader("1\nREVIEWED RETRY\n"))
	f.run = func(flowTask, []string, string, bool) error { t.Fatal("executed tampered command"); return nil }
	if err := f.execute(task); err == nil {
		t.Fatal("accepted arbitrary saved command")
	}
}

func TestRoleFlowHandoffsAreReportedNotVerified(t *testing.T) {
	f := flowFixture(t)
	task := handoff("people", "Confirm human handoff", "Not verification")
	f.stages[0].Tasks = []flowTask{task}
	f.ui.input = bufio.NewReader(strings.NewReader("\n1\n"))
	f.run = func(flowTask, []string, string, bool) error { t.Fatal("handoff ran a command"); return nil }
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if f.last(task).Status != "reported" {
		t.Fatal("human claim overstated")
	}
}

func TestRoleFlowRecoveryDoesNotClaimSuccess(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{ID: "uncertain", Task: task.ID, Stage: "test", Status: "running"}}
	if err := f.execute(task); err == nil || !strings.Contains(err.Error(), "older workflow") {
		t.Fatalf("incomplete old operation was not blocked: %v", err)
	}
	if err := f.advance(); err == nil {
		t.Fatal("advanced incomplete action")
	}
}

func TestGuidedUploadRetainsStableAttemptIdentity(t *testing.T) {
	task := submitFlow("witness", "phase1")
	command := append([]string(nil), task.Command...)
	for _, field := range task.Fields {
		command = append(command, "--"+field.Flag, field.Default)
	}
	prepared, err := prepareRecoveryCommand(task, command, "flow-"+strings.Repeat("a", 32), time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if commandValue(prepared, "attempt-id") != strings.Repeat("a", 32) || commandValue(prepared, "completed-at") != "2026-09-12T01:02:03Z" {
		t.Fatalf("stable upload identity = %q", prepared)
	}
	if err := validateFlowCommand(task, prepared); err != nil {
		t.Fatal(err)
	}
}

func TestGuidedParticipantAllocatesCandidateAttemptBeforeLaunch(t *testing.T) {
	task := flowTask{ID: "contribute", Command: []string{"run"}, Fields: []flowField{
		{Flag: "config", Kind: "host"}, {Flag: "grant", Kind: "host"}, {Flag: "resume-candidate", Kind: "host", Optional: true},
	}}
	command := []string{"run", "--config", "/tmp/participant.json", "--grant", "/tmp/grant.json"}
	prepared, err := prepareRecoveryCommand(task, command, "flow-"+strings.Repeat("d", 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if commandValue(prepared, "attempt-id") != strings.Repeat("d", 32) {
		t.Fatalf("participant attempt identity = %q", prepared)
	}
	if err := validateFlowCommand(task, prepared); err != nil {
		t.Fatal(err)
	}
}

func TestGuidedUploadRecoveryReusesExactAttempt(t *testing.T) {
	f := flowFixture(t)
	task := submitFlow("witness", "phase1")
	command := append([]string(nil), task.Command...)
	for _, field := range task.Fields {
		command = append(command, "--"+field.Flag, field.Default)
	}
	command, err := prepareRecoveryCommand(task, command, "flow-"+strings.Repeat("b", 32), time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	f.ui.input = bufio.NewReader(strings.NewReader("RUN\n"))
	previous := &flowAttempt{ID: "flow-" + strings.Repeat("b", 32), Command: command}
	got, id, retry, err := f.reconcilePrevious(task, previous, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !retry || id != previous.ID || !reflect.DeepEqual(got, command) {
		t.Fatalf("upload recovery changed attempt: retry=%v id=%q command=%q", retry, id, got)
	}
	legacy := append([]string(nil), command[:len(command)-4]...)
	if _, _, _, err := f.reconcilePrevious(task, &flowAttempt{ID: "legacy", Command: legacy}, nil); err == nil || !strings.Contains(err.Error(), "predates stable attempt IDs") {
		t.Fatalf("legacy uncertain upload was repeated: %v", err)
	}
}

func TestParticipantRecoveryUploadsOneRetainedCandidateWithoutRecomputing(t *testing.T) {
	root := t.TempDir()
	candidates := filepath.Join(root, "candidates")
	if err := os.Mkdir(candidates, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(candidates, "phase1-0001-"+strings.Repeat("b", 32))
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "participant-phase1.json")
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchemaV2, Phase: "phase1", Root: filepath.Join(root, "ceremony"),
		Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"),
		CoordinatorKey: filepath.Join(root, "coordinator.hex"), CeremonyBinary: "mpc-ceremony",
		SigningKey: filepath.Join(root, "signing.hex"), Environment: filepath.Join(root, "environment.json"),
		CandidateParentDir: candidates, PublishedBaseURL: "https://ceremony.example", PublishedBucket: "published",
		ExecutionMode: nativeExecutionMode,
	}
	if err := writeJSONNoReplace(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var task flowTask
	for _, stage := range roleFlowStages("participant") {
		if stage.ID != "phase1" {
			continue
		}
		for _, candidateTask := range stage.Tasks {
			if candidateTask.ID == "contribute" {
				task = candidateTask
			}
		}
	}
	if task.ID == "" {
		t.Fatal("participant contribution task not found")
	}
	f := flowFixture(t)
	f.state.Role = "participant"
	f.ui.input = bufio.NewReader(strings.NewReader(filepath.Join(root, "fresh-grant.json") + "\nRUN\n"))
	previous := &flowAttempt{
		ID: "flow-" + strings.Repeat("b", 32), Task: task.ID, Stage: "phase1", Status: "running",
		Command: []string{"run", "--config", configPath, "--grant", filepath.Join(root, "old-grant.json"), "--attempt-id", strings.Repeat("b", 32)},
	}
	got, id, retry, err := f.reconcilePrevious(task, previous, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !retry || id != previous.ID {
		t.Fatalf("participant recovery did not retain operation identity: retry=%v id=%q", retry, id)
	}
	if commandValue(got, "grant") != filepath.Join(root, "fresh-grant.json") || commandValue(got, "resume-candidate") != candidate {
		t.Fatalf("participant recovery command = %q", got)
	}
	if !strings.Contains(f.ui.output.(*bytes.Buffer).String(), "will not be recomputed") {
		t.Fatal("participant recovery did not explain that computation is retained")
	}
}

func TestParticipantRecoveryRefusesAmbiguousRetainedCandidates(t *testing.T) {
	root := t.TempDir()
	candidates := filepath.Join(root, "candidates")
	if err := os.Mkdir(candidates, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		if err := os.Mkdir(filepath.Join(candidates, "phase1-0001-"+attempt), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "participant-phase1.json")
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchemaV2, Phase: "phase1", Root: filepath.Join(root, "ceremony"),
		Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"),
		CoordinatorKey: filepath.Join(root, "coordinator.hex"), CeremonyBinary: "mpc-ceremony",
		SigningKey: filepath.Join(root, "signing.hex"), Environment: filepath.Join(root, "environment.json"),
		CandidateParentDir: candidates, PublishedBaseURL: "https://ceremony.example", PublishedBucket: "published",
		ExecutionMode: nativeExecutionMode,
	}
	if err := writeJSONNoReplace(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{ID: "contribute", Command: []string{"run"}, Fields: []flowField{
		{Flag: "config", Kind: "host"}, {Flag: "grant", Kind: "host"}, {Flag: "resume-candidate", Kind: "host", Optional: true},
	}}
	f := flowFixture(t)
	f.state.Role = "participant"
	previous := &flowAttempt{ID: "flow-" + strings.Repeat("c", 32), Command: []string{"run", "--config", configPath, "--grant", filepath.Join(root, "grant.json")}}
	if _, _, _, err := f.reconcilePrevious(task, previous, nil); err == nil || !strings.Contains(err.Error(), "more than one retained candidate") {
		t.Fatalf("ambiguous retained candidates were accepted: %v", err)
	}
}

func TestGrantRecoveryAdoptsExactWrittenCredential(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	ceremonyID := "sha256:" + strings.Repeat("a", 64)
	storage := access.StorageConfig{
		Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: ceremonyID,
		Endpoint: "https://account.r2.cloudflarestorage.com", Region: "auto", AccountID: "account", ParentAccessKeyID: "parent",
		PublishedBucket: "public", PublishedBaseURL: "https://public.example", InboxBucket: "private", CoordinatorProfile: "default",
		CeremonyPath: "/work/ceremony.json", CeremonySignature: "/work/ceremony.sig", CoordinatorPublicKey: "/trust/coordinator.hex", CeremonyBinary: "mpc-ceremony",
	}
	storagePath := filepath.Join(work, "storage.json")
	if err := writeJSONNoReplace(storagePath, storage, 0o600); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	prefix, err := access.Prefix(ceremonyID, "participant", "participant-01")
	if err != nil {
		t.Fatal(err)
	}
	grant := access.Grant{
		Schema: access.GrantSchema, Provider: "r2", CeremonyID: ceremonyID, Role: "participant", IdentityID: "participant-01",
		Endpoint: storage.Endpoint, Region: storage.Region, InboxBucket: storage.InboxBucket, Prefix: prefix,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(time.Hour).Format(time.RFC3339), MinimumRemaining: "10m0s",
		Credentials: access.SessionCredentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "token"},
	}
	grantPath := filepath.Join(work, "grant.json")
	if err := writeJSONNoReplace(grantPath, grant, 0o600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{ID: "grant", Command: []string{"relay", "coordinator", "grant"}, Fields: []flowField{
		ff("storage", "Storage", "/work/storage.json"), ff("role", "Role", "participant"), ff("identity", "Identity", "participant-01"),
		ff("credential-ttl", "TTL", "1h"), ff("minimum-remaining", "Minimum", "10m"), ff("out", "Grant", "/work/grant.json"),
	}}
	command := []string{"relay", "coordinator", "grant", "--storage", "/work/storage.json", "--role", "participant", "--identity", "participant-01", "--credential-ttl", "1h", "--minimum-remaining", "10m", "--out", "/work/grant.json"}
	f := &roleFlow{
		state:  roleFlowState{Schema: roleFlowSchema, Profile: guidedProfile{Work: work}, Values: map[string]string{}, Attempts: []flowAttempt{{Status: "running", Command: command, StartedAt: issued.Format(time.RFC3339Nano), ExpectedOutputs: map[string]string{"out": grantPath}}}},
		stages: []flowStage{{ID: "turns", Tasks: []flowTask{task}}}, path: filepath.Join(root, "state.json"),
		ui: coordinatorWizard{output: new(bytes.Buffer)},
	}
	previous := &f.state.Attempts[0]
	adopted, err := f.adoptWrittenGrant(task, previous)
	if err != nil || !adopted || previous.Status != "succeeded" {
		t.Fatalf("grant adoption = %v, %#v, %v", adopted, previous, err)
	}
}

func TestRoleFlowExternalRecoveryPreservesUncertainAttempt(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{ID: "uncertain", Task: task.ID, Stage: "test", Status: "running"}}
	f.run = func(flowTask, []string, string, bool) error { t.Fatal("recovery reexecuted the write"); return nil }
	if err := f.execute(task); err == nil {
		t.Fatal("manual completion override was still available")
	}
	if len(f.state.Attempts) != 1 || f.state.Attempts[0].Status != "running" {
		t.Fatal("uncertain operation was rewritten")
	}
}

func TestRoleFlowFieldsAndPaths(t *testing.T) {
	for _, value := range []string{"", "relative", "/etc/passwd", "/work/../keys/private", "/work/input\n--secret"} {
		if validateFlowValue(ff("input", "Input", ""), value) == nil {
			t.Fatal("accepted unsafe path", value)
		}
	}
	if validateFlowValue(flowField{Kind: "number"}, "0") == nil {
		t.Fatal("accepted zero")
	}
	if validateFlowValue(flowField{Kind: "time"}, "yesterday") == nil {
		t.Fatal("accepted vague time")
	}
	p := guidedProfile{Work: "/tmp/ceremony/work", Trust: "/tmp/ceremony/trust", Keys: "/tmp/ceremony/keys"}
	if flowContainerPath(p, "/tmp/ceremony/work/input.json") != "/work/input.json" {
		t.Fatal("host mapping failed")
	}
	if flowContainerPath(p, "/tmp/ceremony/work-other/input.json") == "/work/input.json" {
		t.Fatal("mapped unrelated directory")
	}
	for _, path := range []string{"/work/input.json", "/trust/coordinator.hex", "/keys/signing.hex"} {
		if flowContainerPath(p, flowHostPath(p, path)) != path {
			t.Fatal("display path does not round-trip", path)
		}
	}
	if flowHostPath(p, "/work-other/input.json") != "/work-other/input.json" {
		t.Fatal("mapped unrelated container directory")
	}
}

func TestRoleFlowDuplicateFlagsKeepSeparateDefaults(t *testing.T) {
	f := flowFixture(t)
	task := flowTask{ID: "two-audits", Command: []string{"mpc-ceremony", "release", "sign"}, Fields: []flowField{ff("audit-report", "First", ""), ff("audit-report", "Second", "")}}
	f.ui.input = bufio.NewReader(strings.NewReader("/work/one.json\n/work/two.json\n"))
	if _, err := f.command(task); err != nil {
		t.Fatal(err)
	}
	f.ui.input = bufio.NewReader(strings.NewReader("\n\n"))
	command, err := f.command(task)
	if err != nil {
		t.Fatal(err)
	}
	if command[4] != "/work/one.json" || command[6] != "/work/two.json" {
		t.Fatal("audit defaults collapsed", command)
	}
}

func TestRoleFlowAdditionalAuditPairs(t *testing.T) {
	f := flowFixture(t)
	task := flowTask{ID: "audits", Command: []string{"mpc-ceremony", "release", "sign"}, ExtraLabel: "Additional audits", ExtraFields: []flowField{ff("audit-report", "Report", ""), ff("audit-signature", "Signature", "")}}
	f.ui.input = bufio.NewReader(strings.NewReader("1\n/work/three.json\n/work/three.sig\n"))
	command, err := f.command(task)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFlowCommand(task, command); err != nil {
		t.Fatal(err)
	}
	if err := validateFlowCommand(task, command[:len(command)-2]); err == nil {
		t.Fatal("accepted unpaired report")
	}
}

func TestRoleFlowArtifactDefaultsMatchProofToolLayout(t *testing.T) {
	for _, role := range []string{"coordinator", "witness", "auditor", "release-signer"} {
		for _, stage := range roleFlowStages(role) {
			for _, task := range stage.Tasks {
				for _, field := range task.Fields {
					if strings.HasSuffix(field.Default, "/close.json") || strings.HasSuffix(field.Default, "/beacon.json") {
						t.Fatal("obsolete artifact path", field.Default)
					}
				}
			}
		}
	}
}

func TestRoleFlowPinsPublicInputsNotPrivateKeys(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work, f.state.Profile.Trust = t.TempDir(), t.TempDir()
	path := filepath.Join(f.state.Profile.Work, "ceremony.json")
	if err := os.WriteFile(path, []byte("first ceremony"), 0600); err != nil {
		t.Fatal(err)
	}
	command := []string{"mpc-ceremony", "inspect", "definition", "--ceremony", "/work/ceremony.json", "--coordinator-signing-key", "/keys/must-not-be-read"}
	if err := f.bindPublicInputs(command); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("substituted ceremony"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.bindPublicInputs(command); err == nil {
		t.Fatal("accepted ceremony replacement")
	}
}

func TestRoleFlowTransportProfileUsesSamePinnedCeremony(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	for _, name := range []string{"ceremony.json", "ceremony.sig", "coordinator.hex", "other.json"} {
		if err := os.WriteFile(filepath.Join(f.state.Profile.Work, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.bindPublicInputs([]string{"mpc-ceremony", "inspect", "--ceremony", "/work/ceremony.json"}); err != nil {
		t.Fatal(err)
	}
	config := access.StorageConfig{
		Schema: access.StorageConfigSchema, Provider: "aws", CeremonyID: "sha256:" + strings.Repeat("1", 64),
		PublishedBucket: "public", InboxBucket: "private", PublishedBaseURL: "https://example.invalid",
		CoordinatorProfile: "test", Region: "test", IssuerProfile: "test", GrantRoleARN: "test", GrantRoleMaxTTL: "2h",
		CeremonyPath: "/work/ceremony.json", CeremonySignature: "/work/ceremony.sig",
		CoordinatorPublicKey: "/work/coordinator.hex", CeremonyBinary: "mpc-ceremony",
	}
	path := filepath.Join(f.state.Profile.Work, "storage.json")
	if err := saveJSONAtomic(path, config); err != nil {
		t.Fatal(err)
	}
	command := []string{"relay", "coordinator", "publish", "--storage", "/work/storage.json"}
	if err := f.bindPublicInputs(command); err != nil {
		t.Fatal(err)
	}
	config.CeremonyPath = "/work/other.json"
	if err := saveJSONAtomic(path, config); err != nil {
		t.Fatal(err)
	}
	if err := f.bindPublicInputs(command); err == nil {
		t.Fatal("transport profile switched to a different ceremony")
	}
}

func TestCustodyAndPublicationAppearBeforeDependentActions(t *testing.T) {
	for _, role := range []string{"coordinator", "participant"} {
		for _, stage := range roleFlowStages(role) {
			positions := map[string]int{}
			for i, task := range stage.Tasks {
				positions[task.ID] = i
			}
			for _, pair := range [][2]string{{"verify-outbound-receipt", "grant"}, {"sign-return-receipt", "accept"}, {"sign-outbound-receipt", "contribute"}, {"contribute", "prepare-return-handoff"}, {"seal", "publish-phase1-seal"}, {"publish-phase1-seal", "phase2-init"}, {"beacon", "publish-beacon"}} {
				first, a := positions[pair[0]]
				second, b := positions[pair[1]]
				if a && (!b || first >= second) {
					t.Fatalf("%s/%s: %s must precede %s", role, stage.ID, pair[0], pair[1])
				}
			}
		}
	}
}

func TestReleaseFlowRequiresOneAuditAndAllowsAdditionalPairs(t *testing.T) {
	for _, stage := range roleFlowStages("release-signer") {
		for _, task := range stage.Tasks {
			if task.ID != "sign" {
				continue
			}
			counts := map[string]int{}
			for _, field := range task.Fields {
				if !field.Optional {
					counts[field.Flag]++
				}
			}
			if counts["audit-report"] != 1 || counts["audit-signature"] != 1 {
				t.Fatalf("mandatory audit pairs: %v", counts)
			}
			if len(task.ExtraFields) != 2 || task.ExtraFields[0].Flag != "audit-report" || task.ExtraFields[1].Flag != "audit-signature" {
				t.Fatal("additional audit pairs unavailable")
			}
			return
		}
	}
	t.Fatal("release signing task missing")
}

func TestProductionDecisionGuideRequiresOneAuditorSignature(t *testing.T) {
	for _, stage := range coordinatorFlowStages() {
		if stage.ID != "decision" {
			continue
		}
		for _, task := range stage.Tasks {
			if task.ID != "verify-decision" {
				continue
			}
			auditors := 0
			for _, field := range task.Fields {
				if field.Flag == "signature" && strings.Contains(strings.ToLower(field.Label), "auditor") {
					auditors++
				}
			}
			if auditors != 1 {
				t.Fatalf("mandatory auditor decision signatures = %d, want 1", auditors)
			}
			return
		}
	}
	t.Fatal("coordinator production decision verification task missing")
}
