package main

import (
	"testing"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/upgrade"
)

func TestOperatorSelectionEvidenceDoesNotInventQualification(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	if _, err := upgradeSelectionEvidence(s, d); err != nil {
		t.Fatal(err)
	}
	d.Schema = upgrade.OperatorTransitionSchema
	d.QualificationSHA256 = ""
	d.SafePredecessors = nil
	if _, err := upgradeSelectionEvidence(s, d); err == nil {
		t.Fatal("retained report accepted as operator evidence")
	}
	s.Qualification = nil
	if schema, err := upgradeSelectionEvidence(s, d); err != nil || schema != "" {
		t.Fatalf("invented evidence: %q %v", schema, err)
	}
	s.ApprovalRelease = "role-images-" + d.TargetApp
	if _, err := upgradeSelectionEvidence(s, d); err == nil {
		t.Fatal("operator choice claims approval")
	}
	s.ApprovalRelease = ""
	s.LauncherSHA256 = ""
	if _, err := upgradeSelectionEvidence(s, d); err == nil {
		t.Fatal("accepted missing executable binding")
	}
}

func TestUpgradeInitialRootRequiresExactSignedInitialReferences(t *testing.T) {
	checked := transcript.CheckpointInspectionV4{}
	checked.Checkpoint.CeremonyID = "ceremony"
	checked.CheckpointRefs.Record.Name = "checkpoints/initial/checkpoint.json"
	checked.CheckpointRefs.Record.Digest.SHA256 = "checkpoint-digest"
	checked.CheckpointRefs.Record.Digest.Size = 100
	checked.CheckpointRefs.Signature.Name = "checkpoints/initial/checkpoint.sig"
	checked.CheckpointRefs.Signature.Digest.SHA256 = "signature-digest"
	checked.CheckpointRefs.Signature.Digest.Size = 64
	root := state.Root{CeremonyID: "ceremony", Checkpoint: state.ContentRef{Name: checked.CheckpointRefs.Record.Name, SHA256: "checkpoint-digest", Size: 100}, CheckpointSignature: state.ContentRef{Name: checked.CheckpointRefs.Signature.Name, SHA256: "signature-digest", Size: 64}}
	if err := upgradeMatchInitialRoot(root, checked); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*state.Root){
		"ceremony":          func(r *state.Root) { r.CeremonyID = "another" },
		"checkpoint name":   func(r *state.Root) { r.Checkpoint.Name = "another" },
		"checkpoint digest": func(r *state.Root) { r.Checkpoint.SHA256 = "another" },
		"checkpoint size":   func(r *state.Root) { r.Checkpoint.Size++ },
		"signature name":    func(r *state.Root) { r.CheckpointSignature.Name = "another" },
		"signature digest":  func(r *state.Root) { r.CheckpointSignature.SHA256 = "another" },
		"signature size":    func(r *state.Root) { r.CheckpointSignature.Size++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := root
			change(&bad)
			if upgradeMatchInitialRoot(bad, checked) == nil {
				t.Fatal("accepted different root")
			}
		})
	}
	checked.Checkpoint.Sequence = 1
	if upgradeMatchInitialRoot(root, checked) == nil {
		t.Fatal("accepted later checkpoint without anchor")
	}
}
