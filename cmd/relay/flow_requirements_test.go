package main

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestProductionDecisionCannotBeSkippedAsOptional(t *testing.T) {
	f := flowFixture(t)
	f.stages = []flowStage{decisionFlow("coordinator")}
	f.definition = func() (transcript.Definition, error) { return transcript.Definition{Mode: "production"}, nil }
	if err := f.advance(); err == nil || !strings.Contains(err.Error(), "Prepare the canonical") {
		t.Fatal("skipped required production decision", err)
	}
	if f.state.Stage != 0 {
		t.Fatal("advanced production gate")
	}
}

func TestProductionDecisionMenuMarksEveryDecisionActionRequired(t *testing.T) {
	f := flowFixture(t)
	f.stages = []flowStage{decisionFlow("coordinator")}
	f.definition = func() (transcript.Definition, error) { return transcript.Definition{Mode: "production"}, nil }
	f.ui.input = bufio.NewReader(strings.NewReader("0\n"))
	if err := f.stageMenu(); err != nil {
		t.Fatal(err)
	}
	out := f.ui.output.(*bytes.Buffer).String()
	if !strings.Contains(out, "Suggested next step: 1 — Prepare the canonical GO/NO-GO decision") {
		t.Fatalf("production decision menu suggested the wrong action:\n%s", out)
	}
	if strings.Contains(out, "[Optional]") || !strings.Contains(out, "[Required]") {
		t.Fatalf("production decision actions were not displayed as required:\n%s", out)
	}
}

func TestRehearsalDecisionHiddenOnlyAfterAuthentication(t *testing.T) {
	f := flowFixture(t)
	f.stages = []flowStage{decisionFlow("coordinator")}
	f.definition = func() (transcript.Definition, error) { return transcript.Definition{Mode: "rehearsal"}, nil }
	f.ui.input = bufio.NewReader(strings.NewReader("0\n"))
	if err := f.menu(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.ui.output.(*bytes.Buffer).String(), "actions hidden") {
		t.Fatal("rehearsal actions not hidden")
	}
	if err := f.execute(f.stages[0].Tasks[0]); err == nil {
		t.Fatal("hidden action executable")
	}
	if err := f.advance(); err != nil {
		t.Fatal(err)
	}
	f.state.Stage = 0
	f.definition = func() (transcript.Definition, error) {
		return transcript.Definition{}, errors.New("signature rejected")
	}
	if err := f.advance(); err == nil {
		t.Fatal("unknown mode treated as not applicable")
	}
}

func TestHandoffWaitingDoesNotBecomeCompletion(t *testing.T) {
	f := flowFixture(t)
	task := handoff("sharing", "Share the signed definition through the agreed channel", "Human delivery only")
	f.stages[0].Tasks = []flowTask{task}
	f.ui.input = bufio.NewReader(strings.NewReader("2\n"))
	if err := f.execute(task); err != nil {
		t.Fatal(err)
	}
	if len(f.state.Attempts) != 0 {
		t.Fatal("not yet recorded as completed")
	}
	if err := f.advance(); err == nil {
		t.Fatal("advanced waiting handoff")
	}
}
