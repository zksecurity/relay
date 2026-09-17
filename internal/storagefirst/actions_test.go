package storagefirst

import (
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/state"
)

var recommendationTime = time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)

func actionCheckpoint(sequence uint64, transition, participant string) Checkpoint {
	cp := Checkpoint{
		Position:   state.CheckpointPosition{Sequence: sequence, Digest: digestOfTest(string(rune('1' + sequence)))},
		Transition: transition, ParticipantID: participant, Phase1ScheduledTotal: 2,
		Phase1NextParticipantID: participant,
	}
	cp.authenticatedEvidence = true
	if transition == "phase1-outbound-published" {
		cp.Slots = []Slot{testSlot("receipt", 1, participant, "a", cp.Position.Digest)}
	}
	if transition == "phase1-receipt-accepted" {
		cp.Slots = []Slot{testSlot("candidate", 1, participant, "b", cp.Position.Digest)}
	}
	if transition == "phase1-candidate-accepted" {
		cp.Phase1Accepted = 1
		cp.Phase1NextParticipantID = "participant-2"
		accepted := testSlot("candidate", 1, participant, "b", digestOfTest("3"))
		accepted.Status = "accepted"
		accepted.AcknowledgementDigest = digestOfTest("8")
		cp.Slots = []Slot{accepted}
		cp.AcceptedCandidate = &AcceptedCandidate{
			OperationCheckpointDigest: digestOfTest("3"),
			BasisCheckpointDigest:     accepted.BasisCheckpointDigest, Index: 1, IdentityID: participant,
			AttemptID: accepted.AttemptID, CandidateDigest: digestOfTest("7"),
			AcceptedHeadID: digestOfTest("6"), AcknowledgementDigest: accepted.AcknowledgementDigest,
		}
	}
	return cp
}

func testSlot(kind string, index int, identity, attemptChar, checkpointDigest string) Slot {
	attempt := string(makeHex(attemptChar, 32))
	return Slot{Kind: kind, Phase: "phase1", Index: index, IdentityID: identity, AttemptID: attempt,
		ManifestKey: "submissions/" + kind + "/" + attempt + "/manifest.json", BasisCheckpointDigest: checkpointDigest,
		ParentHeadID: digestOfTest("9"), Status: "allocated"}
}

func TestRecommendRejectsShallowCheckpointProjection(t *testing.T) {
	cp := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	cp.authenticatedEvidence = false
	_, err := RecommendPhase1At(cp, localFor(Participant, "participant-1"), ObservedObjects{}, recommendationTime)
	if err == nil {
		t.Fatal("shallow checkpoint drove role guidance")
	}
}

func localFor(role Role, identity string, facts ...OperationFact) LocalFacts {
	return LocalFacts{Schema: LocalFactsSchema, Role: role, IdentityID: identity, Operations: facts}
}

func operation(kind OperationKind, cp Checkpoint, slot Slot, digest string) OperationFact {
	fact := OperationFact{Kind: kind, CheckpointDigest: cp.Position.Digest, Phase: slot.Phase, Index: slot.Index,
		IdentityID: slot.IdentityID, AttemptID: slot.AttemptID, ArtifactDigest: digest}
	if kind == OperationCandidateGrant {
		fact.GrantExpiresAt = "2026-09-15T02:00:00Z"
	}
	return fact
}

func observed(slot Slot) ObservedObjects {
	return ObservedSubmissions(AuthenticatedObservedSubmission{
		checkpointDigest: slot.BasisCheckpointDigest, slot: slot, manifestDigest: digestOfTest("5"),
	})
}

func TestCoordinatorRecommendationsUseExactScheduledState(t *testing.T) {
	cp0 := actionCheckpoint(0, "", "participant-1")
	cp1 := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	cp2 := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	grant := operation(OperationCandidateGrant, cp2, cp2.Slots[0], digestOfTest("4"))
	cases := []struct {
		name  string
		cp    Checkpoint
		local LocalFacts
		seen  ObservedObjects
		want  Action
		ready bool
	}{
		{"initial", cp0, localFor(Coordinator, "coordinator"), ObservedObjects{}, ActionOpenOutbound, true},
		{"wait exact receipt", cp1, localFor(Coordinator, "coordinator"), ObservedObjects{}, ActionWaitReceipt, false},
		{"accept exact receipt", cp1, localFor(Coordinator, "coordinator"), observed(cp1.Slots[0]), ActionAcceptReceipt, true},
		{"issue exact grant", cp2, localFor(Coordinator, "coordinator"), ObservedObjects{}, ActionIssueGrant, true},
		{"wait exact candidate", cp2, localFor(Coordinator, "coordinator", grant), ObservedObjects{}, ActionWaitCandidate, false},
		{"accept exact candidate", cp2, localFor(Coordinator, "coordinator", grant), observed(cp2.Slots[0]), ActionAcceptCandidate, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RecommendPhase1At(tc.cp, tc.local, tc.seen, recommendationTime)
			if err != nil || got.Action != tc.want || got.Ready != tc.ready {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestParticipantRecommendationsRequireExactDurableFacts(t *testing.T) {
	cp1 := actionCheckpoint(1, "phase1-outbound-published", "participant-1")
	rslot := cp1.Slots[0]
	cp2 := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	cslot := cp2.Slots[0]
	download := operation(OperationOutboundDownloaded, cp1, rslot, digestOfTest("4"))
	receipt := operation(OperationReceiptUploaded, cp1, rslot, digestOfTest("5"))
	grant := operation(OperationCandidateGrant, cp2, cslot, digestOfTest("6"))
	computed := operation(OperationCandidateComputed, cp2, cslot, digestOfTest("7"))
	uploaded := operation(OperationCandidateUploaded, cp2, cslot, computed.ArtifactDigest)
	cases := []struct {
		name  string
		cp    Checkpoint
		facts []OperationFact
		want  Action
		ready bool
	}{
		{"download", cp1, nil, ActionDownloadOutbound, true},
		{"receipt", cp1, []OperationFact{download}, ActionUploadReceipt, true},
		{"wait grant", cp1, []OperationFact{download, receipt}, ActionWaitGrant, false},
		{"grant required", cp2, nil, ActionWaitGrant, false},
		{"contribute", cp2, []OperationFact{grant}, ActionContribute, true},
		{"upload", cp2, []OperationFact{grant, computed}, ActionUploadCandidate, true},
		{"wait acceptance", cp2, []OperationFact{grant, computed, uploaded}, ActionConfirmAcceptance, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RecommendPhase1At(tc.cp, localFor(Participant, "participant-1", tc.facts...), ObservedObjects{}, recommendationTime)
			if err != nil || got.Action != tc.want || got.Ready != tc.ready {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestStaleOrReplacementFactsDoNotAdvanceParticipant(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	slot := cp.Slots[0]
	valid := operation(OperationCandidateGrant, cp, slot, digestOfTest("4"))
	tests := []func(*OperationFact){
		func(f *OperationFact) { f.CheckpointDigest = digestOfTest("f") }, func(f *OperationFact) { f.AttemptID = string(makeHex("e", 32)) },
		func(f *OperationFact) { f.IdentityID = "participant-2" }, func(f *OperationFact) { f.Index = 2 },
		func(f *OperationFact) { f.GrantExpiresAt = "2026-09-15T00:59:59Z" },
	}
	for _, mutate := range tests {
		changed := valid
		mutate(&changed)
		got, err := RecommendPhase1At(cp, localFor(Coordinator, "coordinator", changed), ObservedObjects{}, recommendationTime)
		if err == nil && got.Action != ActionIssueGrant {
			t.Fatalf("stale fact advanced: %+v", got)
		}
	}
	wrongSeen := observed(slot)
	wrongSeen.submissions[0].slot.AttemptID = string(makeHex("e", 32))
	got, err := RecommendPhase1At(cp, localFor(Coordinator, "coordinator", valid), wrongSeen, recommendationTime)
	if err != nil || got.Action != ActionWaitCandidate {
		t.Fatalf("replacement manifest advanced: %+v %v", got, err)
	}
}

func TestExactAcceptanceAndEndOfSchedule(t *testing.T) {
	cp3 := actionCheckpoint(3, "phase1-candidate-accepted", "participant-1")
	accepted := cp3.AcceptedCandidate
	uploaded := OperationFact{Kind: OperationCandidateUploaded, CheckpointDigest: accepted.OperationCheckpointDigest,
		Phase: "phase1", Index: accepted.Index, IdentityID: accepted.IdentityID, AttemptID: accepted.AttemptID, ArtifactDigest: accepted.CandidateDigest}
	got, err := RecommendPhase1At(cp3, localFor(Participant, "participant-1", uploaded), ObservedObjects{}, recommendationTime)
	if err != nil || !got.Ready || got.Action != ActionConfirmAcceptance {
		t.Fatalf("exact acceptance: %+v %v", got, err)
	}
	replacement := uploaded
	replacement.ArtifactDigest = digestOfTest("f")
	got, _ = RecommendPhase1At(cp3, localFor(Participant, "participant-1", replacement), ObservedObjects{}, recommendationTime)
	if got.Ready {
		t.Fatal("different candidate treated as accepted")
	}
	got, _ = RecommendPhase1At(cp3, localFor(Coordinator, "coordinator"), ObservedObjects{}, recommendationTime)
	if got.Action != ActionNextTurn {
		t.Fatalf("next turn = %+v", got)
	}
	cp3.Phase1ScheduledTotal = 1
	cp3.Phase1NextParticipantID = ""
	got, _ = RecommendPhase1At(cp3, localFor(Coordinator, "coordinator"), ObservedObjects{}, recommendationTime)
	if got.Action != ActionClosePhase || !got.Ready {
		t.Fatalf("close recommendation = %+v", got)
	}
}
