package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecisionAnswerShowsChoicesAndAcceptsCaseInsensitiveInput(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "workflow-v4"), 0700); err != nil {
		t.Fatal(err)
	}
	answers := workflowV4DecisionAnswers{Answers: map[string]string{}}
	var output bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("yes\n")), output: &output}
	if err := workflowV4AskDecisionAnswer(ui, work, &answers, "source.reviewed", "Was the source reviewed?", []string{"Yes", "No", "Unknown", "Not reviewed yet"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Was the source reviewed? (Yes / No / Unknown / Not reviewed yet)") {
		t.Fatalf("choices were not displayed: %q", output.String())
	}
	if answers.Answers["source.reviewed"] != "Yes" {
		t.Fatalf("answer was not stored canonically: %q", answers.Answers["source.reviewed"])
	}
	var saved workflowV4DecisionAnswers
	if err := setupReadJSON(workflowV4QuestionnairePath(work), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Answers["source.reviewed"] != "Yes" {
		t.Fatalf("saved answer was not canonical: %q", saved.Answers["source.reviewed"])
	}
}
