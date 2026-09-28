package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecisionGateEditorCorrectsFinalDowngrade(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "workflow-v4"), 0700); err != nil {
		t.Fatal(err)
	}
	answers := workflowV4DecisionAnswers{Schema: workflowV4DecisionQuestionsSchema, Answers: map[string]string{"final.withhold": "No", "final.findings": "Not assessed"}}
	var output bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("2\nNo additional findings within the reviewed scope\n")), output: &output}
	changed, err := decisionEditGate(ui, work, &answers, 8)
	if err != nil || !changed {
		t.Fatalf("edit result: %v, %v", changed, err)
	}
	if answers.Answers["final.findings"] != "No additional findings within the reviewed scope" {
		t.Fatal("field did not change")
	}
	if !strings.Contains(output.String(), "Derived: Unknown because final findings are not established") {
		t.Fatal("downgrade not explained")
	}
	var saved workflowV4DecisionAnswers
	if err := setupReadJSON(workflowV4QuestionnairePath(work), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Answers["final.withhold"] != "No" || saved.Answers["final.findings"] != answers.Answers["final.findings"] {
		t.Fatal("unrelated answer changed or edit was not retained")
	}
}

func TestDecisionGateEditorExampleIsNotDefault(t *testing.T) {
	work := t.TempDir()
	answers := workflowV4DecisionAnswers{Schema: workflowV4DecisionQuestionsSchema, Answers: map[string]string{"source.findings": "Not assessed"}}
	var output bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("4\n\n")), output: &output}
	changed, err := decisionEditGate(ui, work, &answers, 1)
	if err != nil || changed {
		t.Fatalf("Enter must retain saved answer: %v, %v", changed, err)
	}
	if answers.Answers["source.findings"] != "Not assessed" || !strings.Contains(output.String(), "Example (not saved)") {
		t.Fatal("example replaced saved answer")
	}
}
