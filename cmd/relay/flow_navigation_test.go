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

func TestFlowExternalReportIsWaitingNotVerified(t *testing.T) {
	f := flowFixture(t)
	task := f.stages[0].Tasks[0]
	f.state.Attempts = []flowAttempt{{Task: task.ID, Stage: "test", Status: "reported"}}
	if got := f.taskProgress(task); !strings.HasPrefix(got, "Waiting:") {
		t.Fatal(got)
	}
}
