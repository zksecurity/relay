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
	if !strings.Contains(output, "1) Verify definition") || !strings.Contains(output, "NEXT REQUIRED ACTION") {
		t.Fatal("missing explicit recommendation")
	}
	if calls != 0 {
		t.Fatal("navigation ran an unconfirmed action")
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
