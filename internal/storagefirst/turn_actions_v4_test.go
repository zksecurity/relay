package storagefirst

import (
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestV4ParticipantTurnRecommendationsAndRetries(t *testing.T) {
	for _, phase := range []string{"phase1", "phase2"} {
		t.Run(phase, func(t *testing.T) {
			s, p, c, index, e := turnFixtureV4(t, phase)
			schedule, _ := p.Definition.Schedule(phase)
			who := schedule[0]
			view, err := s.TurnV4(p, phase, who)
			if err != nil {
				t.Fatal(err)
			}
			pair := func(name string) transcript.SignedArtifactRefs {
				return transcript.SignedArtifactRefs{Record: transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: sum([]byte(name))}}}
			}
			oldPacket, newPacket := pair("old"), pair("new")
			a, b, candidate := strings.Repeat("ab", 16), strings.Repeat("bc", 16), strings.Repeat("cd", 16)
			index.Turns = []transcript.TurnCommitmentV4{{Scope: view.Scope, Outbounds: []transcript.OutboundCommitmentV4{{CheckpointSequence: 3, PublishedAttemptID: b, Pair: newPacket}, {CheckpointSequence: 1, PublishedAttemptID: a, Pair: oldPacket}}}}
			c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: "receipt", AttemptID: a, Status: "retired"}, {Scope: view.Scope, Kind: "receipt", AttemptID: b, Status: "allocated"}}
			now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
			local := LocalTurnV4{Scope: view.Scope}
			check := func(action string, ready bool) TurnRecommendationV4 {
				t.Helper()
				s := encodeTurnFixtureV4(t, c, index, e)
				r, err := s.RecommendTurnV4(p, phase, Participant, who, local, "", now)
				if err != nil || r.Action != action || r.Ready != ready {
					t.Fatalf("got %+v %v want %s %v", r, err, action, ready)
				}
				return r
			}
			check("download-and-verify-outbound", true)
			local.OutboundSHA256 = newPacket.Record.Digest.SHA256
			check("prepare-and-sign-receipt", true)
			local.ReceiptSHA256 = sum([]byte("receipt"))
			local.ReceiptHandoffSHA256 = oldPacket.Record.Digest.SHA256
			r := check("get-receipt-grant", false)
			if r.Outbound == nil || *r.Outbound != oldPacket {
				t.Fatal("signed receipt relabelled as newest packet")
			}
			local.Grant = &TurnGrantV4{AttemptID: b, ExpiresAt: now.Add(time.Hour)}
			check("upload-receipt", true)
			local.UploadedAttemptID = b
			local.UploadedArtifactID = local.ReceiptSHA256
			check("wait-for-receipt-acceptance", false)
			local.Grant.ExpiresAt = now
			check("wait-for-receipt-acceptance", false) // Expiry does not undo upload.
			c.Sequence += 7
			check("wait-for-receipt-acceptance", false)
			c.Deliveries[1].Status = "accepted"
			index.Turns[0].InputReceipt = &transcript.AcceptedTurnRecordV4{AttemptID: b}
			c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: view.Scope, Kind: "candidate", AttemptID: candidate, Status: "allocated"})
			check("get-candidate-grant", false)
			local.Grant = &TurnGrantV4{AttemptID: candidate, ExpiresAt: now.Add(time.Hour)}
			check("contribute", true)
			// A historical receipt upload is valid above, but it cannot be
			// relabelled as the candidate upload or an unknown attempt.
			validLocal := local
			local.UploadedAttemptID = candidate
			check("inspect-retained-operation", true)
			local.UploadedAttemptID = strings.Repeat("ff", 16)
			check("inspect-retained-operation", true)
			local = validLocal
			local.PendingOperation = true
			check("inspect-retained-operation", true)
			local.PendingOperation = false
			local.ComputedCandidateID = sum([]byte("computed-five-files"))
			check("prepare-and-sign-return-handoff", true)
			// Restart after computation must never suggest another contribution.
			local.PendingOperation = true // A partially written return pair is uncertain.
			check("inspect-retained-operation", true)
			local.PendingOperation = false
			receipt := index.Turns[0].InputReceipt
			deliveries := c.Deliveries
			index.Turns[0].InputReceipt = nil
			c.Deliveries = c.Deliveries[:2]
			check("inspect-retained-operation", true)
			index.Turns[0].InputReceipt = receipt
			c.Deliveries = deliveries
			local.CandidateResultID = sum([]byte("result-seven-files"))
			check("upload-candidate", true)
			validLocal = local
			local.ComputedCandidateID = ""
			check("inspect-retained-operation", true)
			local = validLocal
			local.UploadedAttemptID = candidate
			local.UploadedArtifactID = local.ComputedCandidateID
			check("inspect-retained-operation", true)
			local = validLocal
			local.UploadedAttemptID = candidate
			local.UploadedArtifactID = local.CandidateResultID
			check("wait-for-candidate-acceptance", false)
			c.Deliveries[2].Status = "retired"
			check("wait-for-replacement-attempt", false)
			validLocal = local
			local.CandidateResultID = ""
			local.ComputedCandidateID = ""
			check("inspect-retained-operation", true)
			local = validLocal
			replacement := strings.Repeat("ef", 16)
			c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: view.Scope, Kind: "candidate", AttemptID: replacement, Status: "allocated"})
			check("get-candidate-grant", false)
			local.Grant = &TurnGrantV4{AttemptID: replacement, ExpiresAt: now.Add(time.Hour)}
			check("upload-candidate", true)
			c.Deliveries[2].Status = "rejected"
			c.Deliveries[2].ContributionResultID = local.CandidateResultID
			check("inspect-rejected-result", true)
			c.Deliveries[3].Status = "retired"
			check("inspect-rejected-result", true)
			c.Deliveries[2].Status = "retired"
			c.Deliveries[2].ContributionResultID = ""
			index.Turns[0].AcceptedChain = &transcript.AcceptedChainCommitmentV4{AttemptID: replacement, ContributionResultID: local.CandidateResultID}
			if phase == "phase1" {
				c.Progress.Phase1.AcceptedCount = 1
			} else {
				c.Progress.Phase2.AcceptedCount = 1
			}
			check("turn-complete", false)
			index.Turns[0].AcceptedChain.ContributionResultID = sum([]byte("other"))
			check("inspect-different-accepted-result", true)
			local = LocalTurnV4{Scope: view.Scope}
			check("inspect-accepted-result", true)
		})
	}
}

func TestV4CoordinatorVerifiesSubmissionBeforeRenewingGrant(t *testing.T) {
	s, p, c, index, e := turnFixtureV4(t, "phase1")
	v, err := s.TurnV4(p, "phase1", "")
	if err != nil {
		t.Fatal(err)
	}
	attempt := strings.Repeat("ab", 16)
	index.Turns = []transcript.TurnCommitmentV4{{Scope: v.Scope, Outbounds: []transcript.OutboundCommitmentV4{{PublishedAttemptID: attempt}}}}
	c.Deliveries = []transcript.DeliverySlotV4{{Scope: v.Scope, Kind: "receipt", AttemptID: attempt, Status: "allocated"}}
	s = encodeTurnFixtureV4(t, c, index, e)
	r, err := s.RecommendTurnV4(p, "phase1", Coordinator, "", LocalTurnV4{}, attempt, time.Now())
	if err != nil || r.Action != "verify-and-accept-receipt" {
		t.Fatal(r, err)
	}
	r, err = s.RecommendTurnV4(p, "phase1", Coordinator, "", LocalTurnV4{}, "", time.Now())
	if err != nil || r.Action != "issue-receipt-grant" {
		t.Fatal(r, err)
	}
	c.Deliveries[0].Status = "accepted"
	index.Turns[0].InputReceipt = &transcript.AcceptedTurnRecordV4{AttemptID: attempt}
	candidate := strings.Repeat("bc", 16)
	c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: v.Scope, Kind: "candidate", AttemptID: candidate, Status: "allocated"})
	local := LocalTurnV4{Scope: v.Scope}
	check := func(want string) {
		t.Helper()
		s = encodeTurnFixtureV4(t, c, index, e)
		r, err := s.RecommendTurnV4(p, "phase1", Coordinator, "", local, candidate, time.Now())
		if err != nil || r.Action != want {
			t.Fatal(r, err, want)
		}
	}
	check("download-and-check-candidate")
	local.CandidateResultID = sum([]byte("incoming"))
	check("download-and-check-candidate")
	local.CandidateReceivedAttemptID = candidate
	check("prepare-and-sign-return-receipt")
	local.ReturnReceiptResultID = local.CandidateResultID
	check("verify-and-accept-candidate")
	c.Sequence += 3
	check("verify-and-accept-candidate")
	c.Deliveries[1].Status = "retired"
	candidate = strings.Repeat("ef", 16)
	c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: v.Scope, Kind: "candidate", AttemptID: candidate, Status: "allocated"})
	check("download-and-check-candidate")
	local.CandidateReceivedAttemptID = candidate
	check("verify-and-accept-candidate") // Exact same result and signed receipt can be reused after comparing the new delivery.
}

func TestV4PendingOperationKeepsItsOriginalScope(t *testing.T) {
	s, p, _, _, _ := turnFixtureV4(t, "phase1")
	old := transcript.ContributionScopeV4{CeremonyID: p.Definition.CeremonyID, Phase: "phase1", Index: 1, ParticipantID: "p1", ParentHeadID: sum([]byte("old"))}
	r, err := s.RecommendTurnV4(p, "phase1", Participant, "p2", LocalTurnV4{Scope: old, PendingOperation: true}, "", time.Now())
	if err != nil || r.Action != "inspect-retained-operation" || r.Scope != old {
		t.Fatal("interrupted operation scope was replaced", r, err)
	}
}
