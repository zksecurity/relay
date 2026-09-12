package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestFlowOverviewNamesActionAndKeepsConfirmation(t *testing.T) {
	f := flowFixture(t)
	calls := 0
	f.run = func(flowTask, []string, string, bool) error { calls++; return nil }
	f.ui.input = bufio.NewReader(strings.NewReader("1\n\n\n\nno\n0\n"))
	if err := f.menu(); err != nil {
		t.Fatal(err)
	}
	output := f.ui.output.(*bytes.Buffer).String()
	if !strings.Contains(output, "1) Verify definition") || !strings.Contains(output, "NEXT REQUIRED ACTION") || !strings.Contains(output, "WHY THIS STEP IS NEEDED") || !strings.Contains(output, "Read-only") {
		t.Fatal("missing explicit recommendation")
	}
	if strings.Contains(output, "Relay role procedure") {
		t.Fatal("menu exposed implementation jargon instead of an action-specific explanation")
	}
	if calls != 0 {
		t.Fatal("navigation ran an unconfirmed action")
	}
}

func TestEveryRoleTaskHasAnOperatorFacingWhy(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		for _, stage := range roleFlowStages(role) {
			for _, task := range stage.Tasks {
				why := taskWhy(task, flowReadiness{Requirement: "Required", Source: "Relay role procedure"})
				if why == "" || why != task.Help || strings.Contains(why, "Required by the role's operating procedure") {
					t.Fatalf("%s/%s/%s has no useful why: %q", role, stage.ID, task.ID, why)
				}
			}
		}
	}
}

func TestEveryRoleStageMenuRendersActionSpecificWhy(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		stages := roleFlowStages(role)
		for index, stage := range stages {
			t.Run(role+"/"+stage.ID, func(t *testing.T) {
				f := flowFixture(t)
				f.state.Role, f.state.Name, f.state.Stage = role, "instruction-audit", index
				f.stages = stages
				f.ui.input = bufio.NewReader(strings.NewReader("0\n"))
				if err := f.stageMenu(); err != nil {
					t.Fatal(err)
				}
				out := f.ui.output.(*bytes.Buffer).String()
				if strings.Contains(out, "Required by the role's operating procedure") || strings.Contains(out, "Relay role procedure") {
					t.Fatalf("implementation jargon leaked into %s/%s:\n%s", role, stage.ID, out)
				}
				for _, task := range stage.Tasks {
					source := "Relay role procedure"
					if stage.ID == "decision" {
						source = "authenticated production policy"
					}
					if !strings.Contains(out, task.Label) || !strings.Contains(out, "Why: "+taskWhy(task, flowReadiness{Source: source})) {
						t.Fatalf("missing action-specific reason for %s/%s/%s:\n%s", role, stage.ID, task.ID, out)
					}
					if stage.ID == "decision" && !strings.Contains(out, "[Waiting for authenticated ceremony mode]") {
						t.Fatalf("decision requirement was presented as optional before mode authentication:\n%s", out)
					}
				}
			})
		}
	}
}

func TestFlowAreaNavigationDoesNotCompleteTasks(t *testing.T) {
	f := flowFixture(t)
	f.stages = append(f.stages, flowStage{ID: "storage", Label: "Storage", Tasks: []flowTask{handoff("prepare", "Prepare storage", "Administrator task")}})
	f.ui.input = bufio.NewReader(strings.NewReader("4\n2\n0\n"))
	if err := f.menu(); err != nil {
		t.Fatal(err)
	}
	if f.state.Stage != 1 || len(f.state.Attempts) != 0 {
		t.Fatal("navigation recorded completion")
	}
}

func TestFlowLetterNavigationReturnsToPriorViewWithoutChangingWork(t *testing.T) {
	f := flowFixture(t)
	f.stages = append(f.stages, flowStage{ID: "storage", Label: "Storage", Tasks: []flowTask{handoff("prepare", "Prepare storage", "Administrator task")}})
	// Map → Storage → Back → quit. The only persisted effect of the visit is
	// temporary local navigation history, which Back removes again.
	f.ui.input = bufio.NewReader(strings.NewReader("m\n2\nb\nq\n"))
	if err := f.menu(); err != nil {
		t.Fatal(err)
	}
	if f.state.Stage != 0 || len(f.state.ViewHistory) != 0 || len(f.state.Attempts) != 0 {
		t.Fatalf("letter navigation changed workflow state: %+v", f.state)
	}
	out := f.ui.output.(*bytes.Buffer).String()
	for _, want := range []string{"ACTION", "NAVIGATION", "[V] View this area's actions and requirements", "[M] Ceremony map", "[B] Back to previous view", "[Q] Save and exit"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing navigation control %q:\n%s", want, out)
		}
	}
}

func TestParticipantRecommendationDoesNotSkipWaitingContribution(t *testing.T) {
	stages := roleFlowStages("participant")
	f := flowFixture(t)
	f.state.Role = "participant"
	f.state.Stage = 1 // phase1 contribution; assignment is stage zero.
	f.state.Profile.Work = t.TempDir()
	f.stages = stages
	phase := stages[1]
	// The participant has completed the input custody sequence. Their fresh
	// grant/profile is absent, so contribution is waiting. The later output
	// delivery handoff has no local file prerequisite and used to leapfrog it.
	for _, task := range phase.Tasks[:4] {
		status := "succeeded"
		if task.Handoff {
			status = "reported"
		}
		f.state.Attempts = append(f.state.Attempts, flowAttempt{Task: task.ID, Stage: phase.ID, Status: status})
	}
	f.ui.input = bufio.NewReader(strings.NewReader("q\n"))
	if err := f.menu(); err != nil {
		t.Fatal(err)
	}
	out := f.ui.output.(*bytes.Buffer).String()
	if !strings.Contains(out, "NEXT REQUIRED ACTION\n  Contribute, confirm cleanup and upload") {
		t.Fatalf("contribution was not retained as the next action:\n%s", out)
	}
	if strings.Contains(out, "NEXT REQUIRED ACTION\n  Deliver the public candidate") {
		t.Fatalf("later return handoff leapfrogged the contribution:\n%s", out)
	}
}

func TestLaterStateChangingActionsCannotBypassRequiredOrder(t *testing.T) {
	tests := []struct {
		role, stageID, target, want string
		completeBefore              int
	}{
		{"coordinator", "phase1-turns", "grant", "Prepare outbound custody handoff", 1},
		{"participant", "phase1", "deliver-output", "Contribute, confirm cleanup and upload", 4},
	}
	for _, test := range tests {
		t.Run(test.role+"/"+test.target, func(t *testing.T) {
			f := flowFixture(t)
			f.state.Role = test.role
			f.stages = roleFlowStages(test.role)
			f.run = func(flowTask, []string, string, bool) error {
				t.Fatal("out-of-order action reached execution")
				return nil
			}
			for i, stage := range f.stages {
				if stage.ID == test.stageID {
					f.state.Stage = i
					for _, task := range stage.Tasks[:test.completeBefore] {
						status := "succeeded"
						if task.Handoff {
							status = "reported"
						}
						f.state.Attempts = append(f.state.Attempts, flowAttempt{Task: task.ID, Stage: stage.ID, Status: status})
					}
					for _, task := range stage.Tasks {
						if task.ID == test.target {
							if err := f.execute(task); err == nil || !strings.Contains(err.Error(), test.want) {
								t.Fatalf("later action was not blocked by %q: %v", test.want, err)
							}
							return
						}
					}
				}
			}
			t.Fatal("test stage or action not found")
		})
	}
}

func TestReadOnlyActionMayBeOpenedWithoutCompletingEarlierWork(t *testing.T) {
	f := flowFixture(t)
	f.stages = []flowStage{{ID: "review", Tasks: []flowTask{
		handoff("handoff", "Report handoff", "Report it"),
		{ID: "inspect", Label: "Inspect public state", Help: "Read only", Command: []string{"mpc-ceremony", "inspect", "definition"}},
	}}}
	if err := f.requireTaskPredecessors(f.stages[0].Tasks[1]); err != nil {
		t.Fatalf("read-only inspection was unnecessarily ordered: %v", err)
	}
}

func TestUncertainLaterActionRemainsReachableForRecovery(t *testing.T) {
	f := flowFixture(t)
	first := handoff("first", "Required first step", "Do this first")
	later := flowTask{ID: "later", Label: "Later write", Help: "Writes output", Command: []string{"mpc-ceremony", "ops", "sign"}}
	f.stages = []flowStage{{ID: "recovery", Tasks: []flowTask{first, later}}}
	f.state.Attempts = []flowAttempt{{Task: later.ID, Stage: "recovery", Status: "running"}}
	if err := f.requireTaskPredecessors(later); err != nil {
		t.Fatalf("uncertain action could not be inspected for recovery: %v", err)
	}
}

func TestPreparedLaterActionStillRequiresPredecessors(t *testing.T) {
	f := flowFixture(t)
	first := handoff("first", "Required first step", "Do this first")
	later := flowTask{ID: "later", Label: "Later write", Help: "Writes output", Command: []string{"mpc-ceremony", "ops", "sign"}}
	f.stages = []flowStage{{ID: "recovery", Tasks: []flowTask{first, later}}}
	f.state.Attempts = []flowAttempt{{Task: later.ID, Stage: "recovery", Status: "prepared"}}
	if err := f.requireTaskPredecessors(later); err == nil || !strings.Contains(err.Error(), first.Label) {
		t.Fatalf("never-started action bypassed its predecessor: %v", err)
	}
}

func TestEveryRoleMutationHonorsEarlierRequiredTasks(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		stages := roleFlowStages(role)
		for stageIndex, stage := range stages {
			for taskIndex, task := range stage.Tasks {
				class := flowTaskRecoveryClass(task)
				if taskIndex == 0 || class == recoveryReadOnly || class == recoveryCheckpoint {
					continue
				}
				f := flowFixture(t)
				f.state.Role, f.state.Stage, f.stages = role, stageIndex, stages
				hasRequiredPredecessor := false
				for _, earlier := range stage.Tasks[:taskIndex] {
					r := f.readiness(earlier)
					if r.Requirement != "Optional" && r.Requirement != "Not applicable" {
						hasRequiredPredecessor = true
						break
					}
				}
				if hasRequiredPredecessor && f.requireTaskPredecessors(task) == nil {
					t.Fatalf("%s/%s/%s bypassed an earlier required task", role, stage.ID, task.ID)
				}
			}
		}
	}
}

func TestFlowExternalReportIsWaitingNotVerified(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{Task: task.ID, Stage: "test", Status: "reported"}}
	if got := f.taskProgress(task); !strings.HasPrefix(got, "Waiting:") {
		t.Fatal(got)
	}
}
