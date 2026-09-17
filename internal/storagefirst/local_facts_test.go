package storagefirst

import (
	"path/filepath"
	"testing"
)

func TestExactOperationFactsSurviveRestart(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	grant := operation(OperationCandidateGrant, cp, cp.Slots[0], digestOfTest("4"))
	facts := localFor(Participant, "participant-1", grant)
	path := filepath.Join(t.TempDir(), "workflow", "local-facts.json")
	if err := SaveLocalFacts(path, facts); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadLocalFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RecommendPhase1At(cp, restarted, ObservedObjects{}, recommendationTime)
	if err != nil || got.Action != ActionContribute || !got.Ready {
		t.Fatalf("restart recommendation=%+v err=%v", got, err)
	}
}

func TestRestartedStaleFactDoesNotApplyToReplacementAttempt(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	grant := operation(OperationCandidateGrant, cp, cp.Slots[0], digestOfTest("4"))
	path := filepath.Join(t.TempDir(), "local-facts.json")
	if err := SaveLocalFacts(path, localFor(Participant, "participant-1", grant)); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadLocalFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := cp
	replacement.Slots = append([]Slot(nil), cp.Slots...)
	replacement.Slots[0].AttemptID = string(makeHex("e", 32))
	replacement.Slots[0].ManifestKey = "submissions/candidate/" + replacement.Slots[0].AttemptID + "/manifest.json"
	got, err := RecommendPhase1At(replacement, restarted, ObservedObjects{}, recommendationTime)
	if err != nil || got.Action != ActionWaitGrant || got.Ready {
		t.Fatalf("stale restart fact applied=%+v err=%v", got, err)
	}
}

func TestLocalFactsRejectUnknownFieldsAndCrossIdentityFacts(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	fact := operation(OperationCandidateGrant, cp, cp.Slots[0], digestOfTest("4"))
	facts := localFor(Participant, "participant-2", fact)
	if err := SaveLocalFacts(filepath.Join(t.TempDir(), "facts.json"), facts); err == nil {
		t.Fatal("cross-identity facts saved")
	}
}

func TestSaveLocalFactsRejectsStaleWriterDroppingAnotherOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "facts.json")
	cp := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	first := operation(OperationOutboundDownloaded, cp, cp.Slots[0], digestOfTest("4"))
	second := operation(OperationReceiptUploaded, cp, cp.Slots[0], digestOfTest("5"))
	base := localFor(Participant, "participant-1", first)
	if err := SaveLocalFacts(path, base); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocalFacts(path, localFor(Participant, "participant-1", first, second)); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocalFacts(path, base); err == nil {
		t.Fatal("stale whole-file writer discarded a completed operation")
	}
}
