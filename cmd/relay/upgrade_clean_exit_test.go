package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/upgrade"
)

func TestCleanExitPublicKeyFormatting(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "public.hex"), filepath.Join(dir, "trusted.hex")
	for _, tc := range []struct {
		value string
		same  bool
	}{
		{strings.Repeat("ab", 32) + "\n", true},
		{strings.Repeat("AB", 32), true},
		{strings.Repeat("cd", 32), false},
		{"invalid", false},
	} {
		if err := os.WriteFile(a, []byte(tc.value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
			t.Fatal(err)
		}
		if upgradeSamePublicKey(a, b) != tc.same {
			t.Fatalf("incorrect key comparison for %q", tc.value)
		}
	}
}

func TestCleanExitRefusesMissingEvidenceWithoutSelecting(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	d.OnlineImage = d.OriginalImage
	testUpgradeV2Report(t, &s, &d)
	var q upgrade.QualificationV2
	if err := json.Unmarshal(s.Qualification, &q); err != nil {
		t.Fatal(err)
	}
	q.Schema = upgrade.CleanExitQualificationSchema
	q.Passed = append([]string{}, upgrade.CleanExitQualificationChecks...)
	s.Qualification, _ = json.Marshal(q)
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(s.Qualification)
	s.Declaration, _ = json.Marshal(d)
	before, _ := os.ReadFile(s.StartPath)
	if err := upgradeV2Activate(s, ""); err == nil {
		t.Fatal("admitted update without finished ceremony evidence")
	}
	after, _ := os.ReadFile(s.StartPath)
	if string(before) != string(after) {
		t.Fatal("changed old launcher on refusal")
	}
	if _, err := os.Stat(upgradeV2PointerPath(s.Profile.Work)); !os.IsNotExist(err) {
		t.Fatal("selected refused update")
	}
}

func TestCleanExitRejectsUnacceptedPublicOutput(t *testing.T) {
	s, _ := testUpgradeV2(t, "coordinator")
	inv := upgradeInventory{Files: []upgradeInventoryFile{{Name: "ceremony/public/checkpoints/phase1/partial/checkpoint.json", SHA256: "unused", Size: 10}}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("accepted unpublished checkpoint")
	}
	if err := upgradeCheckCleanFiles(s.Profile, upgradeInventory{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A fully signed earlier intent remains on disk after completion. Only
	// accepted ancestry may clear it, not mere existence of the output file.
	out := filepath.Join(s.Profile.Work, "ceremony/public/checkpoints/old")
	intent := workflowV4CoordinatorIntent{Schema: workflowV4CoordinatorIntentSchema, Action: "allocate", OutputDir: out}
	file := filepath.Join(s.Profile.Work, "workflow-v4/coordinator/old-intent.json")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(intent)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	inv = upgradeInventory{Files: []upgradeInventoryFile{{Name: "workflow-v4/coordinator/old-intent.json"}}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("cleared intent without ancestry")
	}
	child := transcript.CheckpointInspectionV4{}
	child.Checkpoint.PreviousCheckpoint = &intent.Predecessor
	child.Checkpoint.Deliveries = []transcript.DeliverySlotV4{{Scope: intent.Scope, AttemptID: intent.AttemptID, Kind: "candidate", Status: "allocated"}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, map[string]transcript.CheckpointInspectionV4{"checkpoints/old/checkpoint.json": child}, nil); err != nil {
		t.Fatal("blocked completed historical intent", err)
	}
}
