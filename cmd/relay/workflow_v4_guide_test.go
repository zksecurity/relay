package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4RoutingIsIrrevocable(t *testing.T) {
	for _, version := range []int{1, 2, 3, 4} {
		p := guidedProfile{Work: t.TempDir()}
		path := filepath.Join(p.Work, "ceremony", "public", "ceremony.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"schema":"proof-tool-mpc-ceremony-definition-v%d"}`, version)), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := workflowV4RouteHint(p)
		if err != nil || got != (version == 4) {
			t.Fatalf("version %d: %v %v", version, got, err)
		}
		// A retained V4 marker always wins, including a damaged marker: the
		// V4 opener will reject it, not create a second legacy workflow.
		if err := os.WriteFile(filepath.Join(p.Work, ".relay-workspace-v4.json"), []byte("damaged"), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := workflowV4RouteHint(p); err != nil || !got {
			t.Fatal("downgraded existing V4 workspace", err)
		}
	}
	for _, data := range []string{`{`, `{"schema":"future-format"}`, `{"schema":"proof-tool-mpc-ceremony-definition-v4","schema":"proof-tool-mpc-ceremony-definition-v3"}`} {
		p := guidedProfile{Work: t.TempDir()}
		path := filepath.Join(p.Work, "ceremony", "public", "ceremony.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := workflowV4RouteHint(p); err == nil {
			t.Fatal("ambiguous schema allowed legacy route")
		}
	}
}

func TestNormalGuideV4FailureDoesNotTouchLegacyProgress(t *testing.T) {
	settings := t.TempDir()
	p := guidedProfile{Schema: guidedSchema, Name: "test", Role: "coordinator", Work: t.TempDir(), Trust: t.TempDir(), Keys: t.TempDir()}
	dir, err := guidedDirectory(settings, p.Name, p.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "workflow"), 0700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "workflow", "state.json")
	if err := os.WriteFile(legacy, []byte("deliberately invalid legacy state"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// The retained marker selects V4 even with no definition. A missing
	// signing profile must stop before legacy migration or Docker execution.
	if err := os.WriteFile(filepath.Join(p.Work, ".relay-workspace-v4.json"), []byte("marker"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("must not execute"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	err = runRoleFlow([]string{p.Name, "--role", p.Role, "--settings-root", settings})
	if err == nil || !strings.Contains(err.Error(), "network-disabled signing image") {
		t.Fatalf("wrong route: %v", err)
	}
	after, err := os.ReadFile(legacy)
	if err != nil || string(after) != "deliberately invalid legacy state" {
		t.Fatal("legacy state changed", err)
	}
	if _, err := os.Stat(filepath.Join(p.Work, "workflow-v4", "state.json")); !os.IsNotExist(err) {
		t.Fatal("failed authentication created V4 journal", err)
	}
}

func TestWorkflowV4StatusDoesNotInventLocalReadiness(t *testing.T) {
	var out bytes.Buffer
	c := transcript.CheckpointStateV4{Sequence: 8}
	c.Progress.Phase2 = &transcript.CheckpointPhaseState{Phase: "phase2", AcceptedCount: 1}
	turn := storagefirst.TurnViewV4{Stage: storagefirst.TurnCandidateV4, Scope: transcript.ContributionScopeV4{Phase: "phase2", Index: 2, ParticipantID: "participant-test"}}
	pending := &workflowV4Operation{Plan: workflowV4OperationPlan{Kind: "contribute"}, Status: "running"}
	printWorkflowV4Status(&out, "participant", c, turn, pending, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{"Phase 2: 1", "phase2 turn 2", "Retained operation needs inspection", "not be repeated automatically", "mathematics were not replayed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Ready") || strings.Contains(out.String(), "NEXT REQUIRED ACTION") {
		t.Fatal("unimplemented action advertised ready")
	}
}

func TestWorkflowV4PhaseSpecificParticipants(t *testing.T) {
	p := transcript.DefinitionProtocol{}
	p.Definition.Phase1Participants = []string{"phase1-only"}
	p.Definition.Phase2Participants = []string{"phase2-only"}
	for _, tc := range []struct {
		phase, identity string
		want            bool
	}{
		{"phase1", "phase1-only", true}, {"phase1", "phase2-only", false},
		{"phase2", "phase1-only", false}, {"phase2", "phase2-only", true},
		{"phase1", "", true},
	} {
		got, err := workflowV4ScheduledInPhase(p, tc.phase, tc.identity)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %v %v", tc, got, err)
		}
	}
	var output bytes.Buffer
	printWorkflowV4Pending(&output, &workflowV4Operation{Plan: workflowV4OperationPlan{Kind: "contribute"}, Status: "running"})
	if !strings.Contains(output.String(), "contribute (running)") {
		t.Fatal("pending view requires backend snapshot")
	}
}
