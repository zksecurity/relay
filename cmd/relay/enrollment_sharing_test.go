package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestCoordinatorSharesBeforeCollectingEnrollments(t *testing.T) {
	f := flowFixture(t)
	f.state.Role = "coordinator"
	f.stages = coordinatorFlowStages()
	stage := f.stages[0]
	for n, want := range []string{"inspect", "assignments", "enrollment"} {
		if stage.Tasks[n].ID != want {
			t.Fatal("incorrect authored order")
		}
		if got := f.firstUnfinishedRequiredTask(stage, false); got != n {
			t.Fatalf("next=%d want=%d", got, n)
		}
		status := "succeeded"
		if want == "assignments" {
			status = "reported"
		}
		f.state.Attempts = append(f.state.Attempts, flowAttempt{Stage: stage.ID, Task: want, Status: status})
	}
	if got := f.firstUnfinishedRequiredTask(stage, false); got != -1 {
		t.Fatal("old completion IDs lost")
	}
	// History written in the old order retains its meaning after reordering.
	f.state.Attempts[1], f.state.Attempts[2] = f.state.Attempts[2], f.state.Attempts[1]
	if got := f.firstUnfinishedRequiredTask(stage, false); got != -1 {
		t.Fatal("legacy ordering lost completion")
	}
}

func TestSharingUsesSuccessfulInspectionNotUnfinishedInputs(t *testing.T) {
	f := flowFixture(t)
	f.state.Role = "coordinator"
	f.state.Profile.Work = "/example/work"
	f.state.Profile.Trust = "/example/trust"
	want := []string{"/work/custom/definition.json", "/work/custom/definition.sig", "/trust/confirmed.hex"}
	command := []string{"mpc-ceremony", "inspect", "--ceremony", want[0], "--ceremony-signature", want[1], "--coordinator-public-key-file", want[2]}
	f.state.Attempts = []flowAttempt{{Stage: "enrollments", Task: "inspect", Status: "succeeded", Command: command}, {Stage: "enrollments", Task: "inspect", Status: "failed", Command: []string{"--ceremony", "/work/wrong.json"}}}
	f.state.Values["shared/ceremony"] = "/work/unfinished.json"
	task := coordinatorFlowStages()[0].Tasks[1]
	fields := f.handoffFields(task)
	var got []string
	for _, field := range fields {
		got = append(got, field.Default)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong sharing files: %v", got)
	}
	f.showAssignmentFiles(task)
	out := f.ui.output.(*bytes.Buffer).String()
	for _, path := range want {
		if !strings.Contains(out, flowHostPath(f.state.Profile, path)) {
			t.Fatalf("missing exact public path: %s", out)
		}
	}
	if strings.Contains(out, "unfinished") || strings.Contains(out, "wrong.json") {
		t.Fatal("failed prompt replaced verified selection")
	}
	if !strings.Contains(out, "not your entire role folder") {
		t.Fatal("missing public-only scope")
	}
	f.state.Attempts = nil
	f.ui.output = new(bytes.Buffer)
	f.showAssignmentFiles(task)
	if !strings.Contains(f.ui.output.(*bytes.Buffer).String(), "Default file locations") {
		t.Fatal("legacy defaults overclaimed inspection")
	}
}
