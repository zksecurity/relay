package storagefirst

import "testing"

// Each case reconstructs durable facts as a restarted process would. No prior
// evaluator state or unscoped completion flag crosses a boundary.
func TestOnePhase1TurnRecommendationsFromPersistableExactFacts(t *testing.T) {
	participantID := "participant-1"
	cp1 := actionCheckpoint(1, "phase1-outbound-published", participantID)
	cp2 := actionCheckpoint(2, "phase1-receipt-accepted", participantID)
	download := operation(OperationOutboundDownloaded, cp1, cp1.Slots[0], digestOfTest("4"))
	receipt := operation(OperationReceiptUploaded, cp1, cp1.Slots[0], digestOfTest("5"))
	grant := operation(OperationCandidateGrant, cp2, cp2.Slots[0], digestOfTest("6"))
	computed := operation(OperationCandidateComputed, cp2, cp2.Slots[0], digestOfTest("7"))
	uploaded := operation(OperationCandidateUploaded, cp2, cp2.Slots[0], computed.ArtifactDigest)
	views := []struct {
		name  string
		cp    Checkpoint
		facts []OperationFact
		want  Action
		ready bool
	}{
		{"download exact outbound", cp1, nil, ActionDownloadOutbound, true},
		{"upload exact receipt", cp1, []OperationFact{download}, ActionUploadReceipt, true},
		{"wait after exact receipt upload", cp1, []OperationFact{download, receipt}, ActionWaitGrant, false},
		{"contribute with exact unexpired grant", cp2, []OperationFact{grant}, ActionContribute, true},
		{"upload exact retained candidate", cp2, []OperationFact{grant, computed}, ActionUploadCandidate, true},
		{"wait after exact candidate upload", cp2, []OperationFact{grant, computed, uploaded}, ActionConfirmAcceptance, false},
	}
	for _, view := range views {
		t.Run(view.name, func(t *testing.T) {
			got, err := RecommendPhase1At(view.cp, localFor(Participant, participantID, view.facts...), ObservedObjects{}, recommendationTime)
			if err != nil || got.Action != view.want || got.Ready != view.ready {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}
