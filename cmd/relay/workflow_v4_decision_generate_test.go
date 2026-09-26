package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func testGuidedDecisionAnswers() workflowV4DecisionAnswers {
	a := workflowV4DecisionAnswers{
		Schema: workflowV4LegacyDecisionQuestionsSchema, CeremonyID: testHandoffDigest("ceremony"),
		CandidateID: testHandoffDigest("candidate"), CheckpointSHA256: testHandoffDigest("checkpoint"),
		PolicySHA256: testHandoffDigest("policy"), CoordinatorID: "coordinator-1", DecidedAt: "2026-09-25T00:00:00Z",
		Accepted: []workflowV4AcceptedReviewScope{{Phase: "phase1", Position: 1, ParticipantID: "participant-1"}},
		Answers:  map[string]string{"final.withhold": "No", "final.findings": "No additional blocker was reported"},
	}
	for _, prefix := range []string{"source", "rehearsal", "deployment", a.Accepted[0].key() + ".host", a.Accepted[0].key() + ".entropy", a.Accepted[0].key() + ".erasure"} {
		if prefix != "deployment" {
			a.Answers[prefix+".reviewed"] = "Yes"
			a.Answers[prefix+".scope"] = "Specific reviewed checks"
		}
		a.Answers[prefix+".reviewer"] = "Named reviewer"
		a.Answers[prefix+".date"] = "2026-09-25"
		a.Answers[prefix+".findings"] = "No unresolved findings within stated limits"
		a.Answers[prefix+".conclusion"] = "Accept"
		a.Answers[prefix+".blocker"] = "No"
	}
	a.Answers["rehearsal.matching_circuit"] = "Yes"
	for _, field := range []string{"network", "application", "owners", "verification", "activation", "halt", "postcheck"} {
		a.Answers["deployment."+field] = "Specific reviewed deployment detail"
	}
	return a
}

func TestGuidedDecisionStagingResumesExactFilesAndRejectsPartialBytes(t *testing.T) {
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "workflow-v4", "decision"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"decision/evidence/review.md": []byte("reviewed exact evidence")}
	draft := []byte(`{"draft":"exact"}`)
	stage, prepared, err := workflowV4StageDecisionArtifacts(work, files, draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(work, "ceremony", "public", "decision")); !os.IsNotExist(err) {
		t.Fatal("staging entered the canonical public decision tree")
	}
	if _, _, err := workflowV4StageDecisionArtifacts(work, files, draft); err != nil {
		t.Fatalf("exact interrupted staging did not resume: %v", err)
	}
	if err := os.WriteFile(prepared, []byte("partial decision"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := workflowV4StageDecisionArtifacts(work, files, draft); err != nil {
		t.Fatalf("existing output should be retained for validation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stage, "decision", "evidence", "review.md"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := workflowV4StageDecisionArtifacts(work, files, draft); err == nil {
		t.Fatal("partial evidence was silently replaced")
	}
}

func TestGuidedDecisionDerivesGOAndNOGOFromStructuredAnswers(t *testing.T) {
	a := testGuidedDecisionAnswers()
	d := workflowV4DecisionDefinitionFields{CeremonyID: a.CeremonyID, AssurancePolicy: json.RawMessage(`{"public_witnesses_per_phase":0,"mirrors_per_accepted_head":0,"passing_ceremony_audits":0,"external_security_audit_signoffs":0}`), Circuit: json.RawMessage(`{"circuit_id":"synthetic"}`)}
	d.Software.SourceCommit = strings.Repeat("a", 40)
	files, raw, err := workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil {
		t.Fatal(err)
	}
	var draft workflowV4GeneratedDecisionDraft
	if err := json.Unmarshal(raw, &draft); err != nil {
		t.Fatal(err)
	}
	if draft.Decision != "GO" || len(draft.Gates) != 13 || len(files) != 7 || draft.Gates[7].Evidence[0].Name != "decision/evidence/formal-go-no-go-checklist.md" {
		t.Fatalf("unexpected GO draft: decision=%s gates=%d evidence=%d", draft.Decision, len(draft.Gates), len(files))
	}
	if draft.Gates[3].Status != "NOT_REQUIRED" || draft.Gates[4].Status != "NOT_REQUIRED" || draft.Gates[11].Status != "NOT_REQUIRED" || draft.Gates[12].Status != "NOT_REQUIRED" {
		t.Fatal("zero-policy gates were not derived from policy")
	}
	a.Answers[a.Accepted[0].key()+".erasure.blocker"] = "Yes"
	_, raw, err = workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil || json.Unmarshal(raw, &draft) != nil {
		t.Fatal(err)
	}
	if draft.Decision != "NO-GO" || draft.Gates[10].Status != "FAIL" {
		t.Fatal("unresolved cleanup blocker did not prevent GO")
	}
	a.Answers[a.Accepted[0].key()+".erasure.blocker"] = "Unknown"
	_, raw, err = workflowV4BuildDecisionArtifacts(a, d, transcript.SignedArtifactRefs{})
	if err != nil || json.Unmarshal(raw, &draft) != nil {
		t.Fatal(err)
	}
	if draft.Decision != "NO-GO" || draft.Gates[10].Status != "PENDING" {
		t.Fatal("unknown cleanup outcome did not prevent GO")
	}
}

func TestGuidedDecisionRejectsIncompleteOrAlteredAnswers(t *testing.T) {
	a := testGuidedDecisionAnswers()
	d := workflowV4DecisionDefinitionFields{CeremonyID: a.CeremonyID, AssurancePolicy: json.RawMessage(`{"public_witnesses_per_phase":0,"mirrors_per_accepted_head":0,"passing_ceremony_audits":0,"external_security_audit_signoffs":0}`), Circuit: json.RawMessage(`{"circuit_id":"synthetic"}`)}
	d.Software.SourceCommit = strings.Repeat("a", 40)
	for name, change := range map[string]func(*workflowV4DecisionAnswers){
		"missing deployment step": func(a *workflowV4DecisionAnswers) { delete(a.Answers, "deployment.halt") },
		"invented gate answer":    func(a *workflowV4DecisionAnswers) { a.Answers["source.reviewed"] = "Definitely" },
		"unknown field":           func(a *workflowV4DecisionAnswers) { a.Answers["source.secret"] = "extra" },
		"duplicate scope": func(a *workflowV4DecisionAnswers) {
			a.Accepted = append(a.Accepted, a.Accepted[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := a
			copy.Answers = make(map[string]string, len(a.Answers))
			for key, value := range a.Answers {
				copy.Answers[key] = value
			}
			change(&copy)
			if _, _, err := workflowV4BuildDecisionArtifacts(copy, d, transcript.SignedArtifactRefs{}); err == nil {
				t.Fatal("invalid questionnaire produced a draft")
			}
		})
	}
}
