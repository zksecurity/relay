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
				if role == "participant" {
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
	f.ui.input = bufio.NewReader(strings.NewReader("1\nREVIEWED RETRY\n"))
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
	f.ui.input = bufio.NewReader(strings.NewReader("\nSent public evidence to the coordinator\nCONFIRMED\n"))
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
	f.ui.input = bufio.NewReader(strings.NewReader("2\nNo signed output; prepared corrected input in a fresh directory\nREVIEWED\n"))
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if f.last(task).Status != "reviewed-incomplete" {
		t.Fatal("recovery marked command complete")
	}
	if err := f.advance(); err == nil {
		t.Fatal("advanced incomplete action")
	}
}

func TestRoleFlowExternalRecoveryPreservesUncertainAttempt(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{ID: "uncertain", Task: task.ID, Stage: "test", Status: "running"}}
	f.ui.input = bufio.NewReader(strings.NewReader("3\nVerified exact signed output with proof-tool; retained verification log\nRECOVERY VERIFIED\n"))
	f.run = func(flowTask, []string, string, bool) error { t.Fatal("recovery reexecuted the write"); return nil }
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if len(f.state.Attempts) != 2 || f.state.Attempts[0].Status != "running" || f.last(task).Status != "reported" {
		t.Fatal("lost uncertainty or overstated report")
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
