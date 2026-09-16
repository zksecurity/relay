package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4LifecycleClosesOnlyCompletedOpenPhase(t *testing.T) {
	protocol := transcript.DefinitionProtocol{Definition: transcript.Definition{Phase1Participants: []string{"p1"}, Phase2Participants: []string{"p1"}}}
	state := transcript.CheckpointStateV4{Progress: transcript.CheckpointProgressV4{Phase1: transcript.CheckpointPhaseState{Phase: "phase1"}}}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != "" {
		t.Fatalf("unfinished phase action = %q, %v", action, err)
	}
	state.Progress.Phase1.AcceptedCount = 1
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4ClosePhase1 {
		t.Fatalf("completed phase1 action = %q, %v", action, err)
	}
	state.Progress.Phase1Closure = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4BeaconPhase1 {
		t.Fatalf("closed phase1 action = %q, %v", action, err)
	}
	state.Progress.Phase1Beacon = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4SealPhase1 {
		t.Fatalf("beacon phase1 action = %q, %v", action, err)
	}
	state.Progress.Phase1Seal = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4StartPhase2 {
		t.Fatalf("sealed phase1 action = %q, %v", action, err)
	}
	state.Progress.Phase2 = &transcript.CheckpointPhaseState{Phase: "phase2", AcceptedCount: 1}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4ClosePhase2 {
		t.Fatalf("completed phase2 action = %q, %v", action, err)
	}
	state.Progress.Phase2Closure = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4BeaconPhase2 {
		t.Fatalf("closed phase2 action = %q, %v", action, err)
	}
	state.Progress.Phase2Beacon = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != workflowV4Finalize {
		t.Fatalf("completed ceremony action = %q, %v", action, err)
	}
	state.Progress.FinalCandidate = &transcript.SignedArtifactRefs{}
	if action, _, err := workflowV4CoordinatorLifecycleAction(state, protocol); err != nil || action != "" {
		t.Fatalf("final candidate should wait for release signer, action = %q, %v", action, err)
	}
}

func TestWorkflowV4SealAndPhase2CommandsUseAuthenticatedPairs(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	online := guidedProfile{Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Work: work, Trust: trust, Keys: keys}
	closure, beacon, seal := pairV4Test("closure"), pairV4Test("beacon"), pairV4Test("seal")
	sealCommand, err := workflowV4SealCommand(online, signer, closure, beacon, filepath.Join(work, "ceremony", "public", "phase1", "sealed"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sealCommand, " ")
	for _, want := range []string{"phase1 seal", "--closure /work/ceremony/public/" + closure.Record.Name, "--beacon /work/ceremony/public/" + beacon.Record.Name, "--out-dir /work/ceremony/public/phase1/sealed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("seal command %q lacks %q", joined, want)
		}
	}
	phase2Command, err := workflowV4Phase2InitCommand(online, signer, seal, filepath.Join(work, "ceremony", "public", "phase2"))
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(phase2Command, " ")
	for _, want := range []string{"phase2 init", "--phase1-seal /work/ceremony/public/" + seal.Record.Name, "--out-dir /work/ceremony/public/phase2"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("phase2 command %q lacks %q", joined, want)
		}
	}
}

func TestWorkflowV4BeaconCommandUsesCommittedClosure(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	online := guidedProfile{Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Work: work, Trust: trust, Keys: keys}
	closure := pairV4Test("phase1-closure")
	response := filepath.Join(work, "workflow-v4", "beacons", "phase1-round-10.json")
	when := time.Date(2026, 9, 16, 1, 2, 3, 4, time.UTC)
	command, err := workflowV4BeaconCommand(online, signer, "phase1", closure, response, when)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{
		"mpc-ceremony phase1 beacon",
		"--closure /work/ceremony/public/" + closure.Record.Name,
		"--closure-signature /work/ceremony/public/" + closure.Signature.Name,
		"--raw-response /work/workflow-v4/beacons/phase1-round-10.json",
		"--published-at " + when.Format(time.RFC3339Nano),
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q lacks %q", joined, want)
		}
	}
}

func TestWorkflowV4CloseCommandUsesAuthenticatedPhaseFiles(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	online := guidedProfile{Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Work: work, Trust: trust, Keys: keys}
	phase := transcript.CheckpointPhaseState{Phase: "phase1", Chain: pairV4Test("phase1-chain")}
	command, err := workflowV4CloseCommand(transcript.CheckpointStateV4{}, online, signer, "phase1", phase, 37)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{
		"mpc-ceremony phase1 close",
		"--transcript-dir /work/ceremony/public",
		"--chain " + filepath.ToSlash(filepath.Join("/work", "ceremony", "public", phase.Chain.Record.Name)),
		"--chain-signature " + filepath.ToSlash(filepath.Join("/work", "ceremony", "public", phase.Chain.Signature.Name)),
		"--beacon-round-lead 37",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("command %q lacks %q", joined, want)
		}
	}
}

func TestWorkflowV4FinalizeCommandsUseCompleteAuthenticatedReplay(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	online := guidedProfile{Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Work: work, Trust: trust, Keys: keys}
	state := transcript.CheckpointStateV4{CeremonyID: "sha256:" + strings.Repeat("a", 64)}
	state.Progress.Phase1 = transcript.CheckpointPhaseState{Phase: "phase1", Chain: pairV4Test("phase1/chain")}
	state.Progress.Phase1Closure = pointerPairV4Test("phase1/closure")
	state.Progress.Phase1Beacon = pointerPairV4Test("phase1/beacon")
	state.Progress.Phase1Seal = pointerPairV4Test("phase1/seal")
	state.Progress.Phase2 = &transcript.CheckpointPhaseState{Phase: "phase2", Chain: pairV4Test("phase2/chain")}
	state.Progress.Phase2Closure = pointerPairV4Test("phase2/closure")
	state.Progress.Phase2Beacon = pointerPairV4Test("phase2/beacon")
	when := time.Date(2026, 9, 16, 1, 2, 3, 4, time.UTC)
	output := filepath.Join(work, "ceremony", "public", "final", "candidate")
	evidence := filepath.Join(work, "ceremony", "public", "final", "public-finalization-evidence.json")
	command, err := workflowV4FinalizeCommand(state, online, signer, "complete", output, evidence, when)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{
		"mpc-ceremony finalize complete",
		"--phase1-chain /work/ceremony/public/" + state.Progress.Phase1.Chain.Record.Name,
		"--phase1-seal /work/ceremony/public/" + state.Progress.Phase1Seal.Record.Name,
		"--phase2-chain /work/ceremony/public/" + state.Progress.Phase2.Chain.Record.Name,
		"--phase2-beacon /work/ceremony/public/" + state.Progress.Phase2Beacon.Record.Name,
		"--public-evidence /work/ceremony/public/final/public-finalization-evidence.json",
		"--out-dir /work/ceremony/public/final/candidate",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("finalize command %q lacks %q", joined, want)
		}
	}
}

func pointerPairV4Test(name string) *transcript.SignedArtifactRefs {
	pair := pairV4Test(name)
	return &pair
}
