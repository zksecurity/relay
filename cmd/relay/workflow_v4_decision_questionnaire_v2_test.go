package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func testGuidedDecisionAnswersV2(scopes int) workflowV4DecisionAnswers {
	a := testGuidedDecisionAnswers()
	a.Schema = workflowV4DecisionQuestionsSchema
	a.Answers = map[string]string{}
	a.Accepted = nil
	for i := 0; i < scopes; i++ {
		phase := "phase1"
		if i >= scopes/2 {
			phase = "phase2"
		}
		a.Accepted = append(a.Accepted, workflowV4AcceptedReviewScope{Phase: phase, Position: uint8(i + 1), ParticipantID: "participant-" + string(rune('a'+i))})
	}
	for _, q := range workflowV4DecisionQuestionsV2(a) {
		value := q.fallback
		switch {
		case strings.HasSuffix(q.key, ".reviewer_date"):
			value = "Named reviewer; 2026-09-26 UTC"
		case strings.HasPrefix(q.key, "contribution.") && strings.HasSuffix(q.key, ".outcome"):
			value = workflowV4RowCovered
		case strings.HasSuffix(q.key, ".status"), strings.HasSuffix(q.key, ".outcome"):
			value = workflowV4ReviewClear
		case q.key == "rehearsal.match", q.key == "assurance.coverage":
			value = "Yes"
		case q.key == "final.withhold":
			value = "No"
		case q.key == "deployment.target":
			value = "Cardano mainnet; Refund verifier"
		case len(q.choices) == 0:
			value = "Concrete reviewed checks and no unresolved findings"
		}
		a.Answers[q.key] = value
	}
	return a
}

func TestGuidedDecisionV2CompactQuestionsAndPerContributionOutcome(t *testing.T) {
	a := testGuidedDecisionAnswersV2(6)
	if got := len(workflowV4DecisionQuestionsV2(a)); got != 54 {
		t.Fatalf("six contributions should have 54 main questions, got %d", got)
	}
	d := workflowV4DecisionDefinitionFields{CeremonyID: a.CeremonyID, AssurancePolicy: json.RawMessage(`{"public_witnesses_per_phase":0,"mirrors_per_accepted_head":0,"passing_ceremony_audits":0,"external_security_audit_signoffs":0}`), Circuit: json.RawMessage(`{"circuit_id":"synthetic"}`)}
	d.Software.SourceCommit = strings.Repeat("a", 40)
	_, raw, err := workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil {
		t.Fatal(err)
	}
	var draft workflowV4GeneratedDecisionDraft
	if err := json.Unmarshal(raw, &draft); err != nil || draft.Decision != "GO" {
		t.Fatalf("complete V2 reviews did not yield draft GO: %v %s", err, draft.Decision)
	}
	row := "contribution." + a.Accepted[3].key()
	a.Answers[row+".host_label"] = "Changed host"
	a.Answers[row+".details"] = "New host checked; cleanup issue remains"
	a.Answers[row+".erasure.reviewer_date"] = "Cleanup reviewer; 2026-09-26 UTC"
	a.Answers[row+".erasure.outcome"] = "Rejected"
	_, raw, err = workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil || json.Unmarshal(raw, &draft) != nil {
		t.Fatal(err)
	}
	if draft.Decision != "NO-GO" || draft.Gates[10].Status != "FAIL" || draft.Gates[8].Status != "PASS" {
		t.Fatalf("per-contribution exception was not isolated: %s %s %s", draft.Decision, draft.Gates[10].Status, draft.Gates[8].Status)
	}
	a.Answers[row+".erasure.outcome"] = workflowV4RowSeparate
	a.Answers["assurance.coverage"] = "No"
	_, raw, err = workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil || json.Unmarshal(raw, &draft) != nil {
		t.Fatal(err)
	}
	if draft.Decision != "NO-GO" || draft.Gates[8].Status != "PENDING" {
		t.Fatal("a shared review without coverage authorized untouched contributions")
	}
}

func TestGuidedDecisionV2DefaultsCannotProduceGOAndChoicesRetry(t *testing.T) {
	a := testGuidedDecisionAnswersV2(2)
	for _, q := range workflowV4DecisionQuestionsV2(a) {
		a.Answers[q.key] = q.fallback
	}
	if _, err := workflowV4ExpandDecisionAnswersV2(a); err != nil {
		t.Fatal(err)
	}
	d := workflowV4DecisionDefinitionFields{CeremonyID: a.CeremonyID, AssurancePolicy: json.RawMessage(`{"public_witnesses_per_phase":0,"mirrors_per_accepted_head":0,"passing_ceremony_audits":0,"external_security_audit_signoffs":0}`), Circuit: json.RawMessage(`{"circuit_id":"synthetic"}`)}
	d.Software.SourceCommit = strings.Repeat("a", 40)
	_, raw, err := workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil {
		t.Fatal(err)
	}
	var draft workflowV4GeneratedDecisionDraft
	if json.Unmarshal(raw, &draft) != nil || draft.Decision != "NO-GO" {
		t.Fatal("safe defaults must not produce GO")
	}
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "workflow-v4"), 0700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("invalid\n1\n:save\n")), output: &output}
	a.Answers = map[string]string{}
	if err := workflowV4AskDecisionQuestionsV2(ui, work, &a); err != errWorkflowV4DecisionQuestionnaireSaved {
		t.Fatalf("expected saved questionnaire: %v", err)
	}
	if a.Answers["source.status"] != workflowV4ReviewClear || !strings.Contains(output.String(), "this answer was not saved") || !strings.Contains(output.String(), "Example (not saved)") {
		t.Fatal("invalid choice did not retry or examples were not distinguished")
	}
}

func TestGuidedDecisionV2BlockerAndDistinctTopicReviewers(t *testing.T) {
	a := testGuidedDecisionAnswersV2(2)
	a.Answers["assurance.host.reviewer_date"] = "Host reviewer; 2026-09-24 UTC"
	a.Answers["assurance.erasure.reviewer_date"] = "Cleanup reviewer; 2026-09-25 UTC"
	expanded, err := workflowV4ExpandDecisionAnswersV2(a)
	if err != nil {
		t.Fatal(err)
	}
	row := a.Accepted[0].key()
	if expanded.Answers[row+".host.reviewer"] != "Host reviewer" || expanded.Answers[row+".erasure.reviewer"] != "Cleanup reviewer" {
		t.Fatal("distinct topic reviewers were incorrectly merged")
	}
	a.Answers["assurance.erasure.outcome"] = workflowV4ReviewBlocked
	a.Answers["contribution."+row+".erasure.outcome"] = workflowV4ReviewBlocked
	a.Answers["contribution."+row+".details"] = "Owner reported a retained backup; unresolved"
	a.Answers["contribution."+row+".erasure.reviewer_date"] = "Cleanup reviewer; 2026-09-25 UTC"
	expanded, err = workflowV4ExpandDecisionAnswersV2(a)
	if err != nil {
		t.Fatal(err)
	}
	if expanded.Answers[row+".erasure.blocker"] != "Yes" || expanded.Answers[row+".erasure.conclusion"] != "Accept" {
		t.Fatal("review accepted with unresolved blocker was silently cleared")
	}
}

func TestGuidedDecisionLoadsFrozenV1Questionnaire(t *testing.T) {
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := testGuidedDecisionAnswers()
	if err := os.MkdirAll(filepath.Join(work, "workflow-v4"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveJSONAtomic(workflowV4QuestionnairePath(work), a); err != nil {
		t.Fatal(err)
	}
	binding := a
	binding.Schema = workflowV4DecisionQuestionsSchema
	binding.DecidedAt = ""
	binding.Answers = nil
	loaded, err := workflowV4LoadDecisionAnswers(work, binding)
	if err != nil || loaded.Schema != workflowV4LegacyDecisionQuestionsSchema || loaded.DecidedAt != a.DecidedAt {
		t.Fatalf("saved V1 questionnaire was not resumed exactly: %v", err)
	}
	if err := workflowV4RetainDecisionPreparationIntent(work, a, map[string][]byte{"decision/evidence/review.md": []byte("review")}, []byte("draft")); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4RetainDecisionPreparationIntent(work, a, map[string][]byte{"decision/evidence/review.md": []byte("review")}, []byte("draft")); err != nil {
		t.Fatalf("exact frozen preparation could not resume: %v", err)
	}
	a.DecidedAt = "2026-09-26T01:00:00Z"
	if err := saveJSONAtomic(workflowV4QuestionnairePath(work), a); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4RetainDecisionPreparationIntent(work, a, map[string][]byte{"decision/evidence/review.md": []byte("review")}, []byte("draft")); err == nil {
		t.Fatal("changed frozen questionnaire was accepted")
	}
}
