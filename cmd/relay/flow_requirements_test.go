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

func policyDefinition(witnesses, mirrors, audits int, lead uint32) transcript.Definition {
	j := observerTestJourney()
	j.Schema = "proof-tool-mpc-definition-journey-v2"
	j.MinimumPublicWitnesses = witnesses
	j.MinimumMirrorsPerAcceptedHead = mirrors
	j.MinimumPassingCeremonyAudits = audits
	j.MinimumExternalAuditSignoffs = 0
	j.BeaconRoundLeadSeconds = lead
	if audits == 0 {
		filtered := j.RequiredEnrollments[:0]
		for _, enrollment := range j.RequiredEnrollments {
			if enrollment.Role != "auditor" {
				filtered = append(filtered, enrollment)
			}
		}
		j.RequiredEnrollments = filtered
	}
	return transcript.Definition{Mode: "production", Journey: j}
}

func TestSignedAssuranceControlsGuidedTasks(t *testing.T) {
	f := flowFixture(t)
	f.definition = func() (transcript.Definition, error) { return policyDefinition(0, 0, 0, 17), nil }
	witness := assurance(handoff("witnesses-ready", "Witnesses", "Only when enabled"), "witness")
	f.stages[0].Tasks = []flowTask{witness}
	if got := f.readiness(witness); got.Requirement != "Not applicable" {
		t.Fatalf("disabled witness task = %#v", got)
	}
	if err := f.execute(witness); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("disabled witness task executed", err)
	}

	close := withFields(flowProof("close", "Close", "Close", "phase1", "close"), flowField{Flag: "beacon-round-lead", Default: "300", Kind: "number"})
	resolved, applicable, err := f.resolvePolicyTask(close)
	if err != nil || !applicable || resolved.Fields[3].Default != "17" {
		t.Fatalf("signed beacon lead not selected: %#v %v", resolved.Fields, err)
	}

	ops := withFields(flowProof("ops-prepare", "Evidence", "Evidence", "ops", "prepare-bundle"), flowField{Flag: "witness-quorum", Default: "1", Kind: "number"})
	resolved, _, err = f.resolvePolicyTask(ops)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range resolved.Fields {
		if field.Flag == "witness-quorum" {
			t.Fatal("operator-controlled witness quorum remained")
		}
	}
}

func TestZeroAuditPolicyRemovesReleaseInputsAndDisablesAuditor(t *testing.T) {
	f := flowFixture(t)
	f.state.Role = "release-signer"
	f.definition = func() (transcript.Definition, error) { return policyDefinition(0, 0, 0, 17), nil }
	var sign flowTask
	for _, stage := range roleFlowStages("release-signer") {
		for _, task := range stage.Tasks {
			if task.ID == "sign" {
				sign = task
			}
		}
	}
	resolved, applicable, err := f.resolvePolicyTask(sign)
	if err != nil || !applicable {
		t.Fatal(err)
	}
	for _, field := range resolved.Fields {
		if field.Flag == "audit-report" || field.Flag == "audit-signature" {
			t.Fatal("disabled audit input remained")
		}
	}
	if len(resolved.ExtraFields) != 0 {
		t.Fatal("disabled additional audit inputs remained")
	}
	f.state.Role = "auditor"
	if err := f.requireEnabledRole(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("disabled auditor role opened", err)
	}
}
