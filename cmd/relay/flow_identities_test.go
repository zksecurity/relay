package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestFlowIdentityChoicesUsePublicDisplayNames(t *testing.T) {
	p := preparationFixture(t, "auditor")
	prepareTestIdentity(t, p)
	f := flowFixture(t)
	f.state.Role = "auditor"
	f.state.Profile.Keys = p.d.Keys
	choices, err := f.identityChoices(flowTask{}, ft("auditor-id", "Auditor", ""))
	if err != nil || len(choices) != 1 || choices[0].value != "my-id" || choices[0].label != "My name (my-id)" {
		t.Fatalf("%v %v", choices, err)
	}
	// The helper reads only the public identity, never the private seed.
	if _, err := os.Stat(filepath.Join(p.d.Keys, "signing.hex")); !os.IsNotExist(err) {
		t.Fatal("test unexpectedly has a signing key")
	}
	f.state.Profile.Keys = ""
	choices, err = f.identityChoices(flowTask{}, ft("auditor-id", "Auditor", ""))
	if err != nil || len(choices) != 0 {
		t.Fatal("invented an identity without a local public file")
	}
}

func TestScheduledTurnParticipantShowsAuthenticatedOrderAndLocksExpectedTurn(t *testing.T) {
	f := flowFixture(t)
	f.state.Role = "coordinator"
	f.state.Profile.Work = t.TempDir()
	f.stages = []flowStage{{ID: "phase1-turns", Tasks: []flowTask{{ID: "grant"}}}}
	f.turnScope = &flowTurnScope{Phase: "phase1", Participant: "participant-b", Head: "sha256:head"}
	f.definition = func() (transcript.Definition, error) {
		return transcript.Definition{Phase1Participants: []string{"participant-a", "participant-b", "participant-c"}}, nil
	}
	for _, input := range []struct {
		task  flowTask
		field flowField
	}{
		{flowTask{ID: "prepare-outbound-handoff"}, ft("participant-id", "Next scheduled participant ID", "")},
		{flowTask{ID: "grant"}, ft("identity", "Next participant ID", "")},
	} {
		choices, expected, err := f.scheduledTurnParticipant(input.task, input.field)
		if err != nil || expected != "participant-b" || len(choices) != 3 {
			t.Fatalf("choices=%v expected=%q err=%v", choices, expected, err)
		}
		if choices[0].value != "participant-a" || choices[1].value != "participant-b" || choices[2].value != "participant-c" || choices[1].label != "2. participant-b — expected next" {
			t.Fatalf("unexpected authenticated schedule display: %+v", choices)
		}
	}
}
