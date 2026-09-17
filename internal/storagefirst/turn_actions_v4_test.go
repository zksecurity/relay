package storagefirst

import (
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func enrolledTurnV4(t *testing.T, phase string) (SnapshotV4, transcript.DefinitionProtocol, transcript.CheckpointStateV4, transcript.CheckpointCommitmentsV4, transcript.EnrollmentMetadataV4, TurnViewV4) {
	t.Helper()
	_, p, c, index, enrollments := turnFixtureV4(t, phase)
	schedule, _ := p.Definition.Schedule(phase)
	for _, required := range p.Definition.Journey.RequiredEnrollments {
		if required.Identity.ID == schedule[0] {
			enrollments.Enrollments = append(enrollments.Enrollments, transcript.CommittedEnrollmentMetadataV4{Enrollment: transcript.EnrollmentInspection{Role: required.Role, RoleIndex: required.RoleIndex, Identity: required.Identity}})
		}
	}
	s := encodeTurnFixtureV4(t, c, index, enrollments)
	view, err := s.TurnV4(p, phase, schedule[0])
	if err != nil || view.Stage != TurnAllocationV4 {
		t.Fatal(view, err)
	}
	return s, p, c, index, enrollments, view
}

func TestV4ParticipantTurnRecommendationsAndRetries(t *testing.T) {
	for _, phase := range []string{"phase1", "phase2"} {
		t.Run(phase, func(t *testing.T) {
			_, p, c, index, enrollments, view := enrolledTurnV4(t, phase)
			who := view.Scope.ParticipantID
			now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
			attempt := strings.Repeat("ab", 16)
			index.Turns = []transcript.TurnCommitmentV4{{Scope: view.Scope, Allocations: []transcript.CandidateAllocationV4{{CheckpointSequence: 1, Checkpoint: allocationPairV4(1), AttemptID: attempt, AllocatedAt: now.Format(time.RFC3339)}}}}
			c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: "candidate", AttemptID: attempt, Status: "allocated"}}
			local := LocalTurnV4{Scope: view.Scope}
			check := func(action string, ready bool) TurnRecommendationV4 {
				t.Helper()
				s := encodeTurnFixtureV4(t, c, index, enrollments)
				r, err := s.RecommendTurnV4(p, phase, Participant, who, local, "", now)
				if err != nil || r.Action != action || r.Ready != ready {
					t.Fatalf("got %+v %v want %s %v", r, err, action, ready)
				}
				return r
			}
			check("contribute", true)
			local.PendingOperation = true
			check("inspect-retained-operation", true)
			local.PendingOperation = false
			local.GeneratedOutput = &transcript.ComputationOutputFactsV4{Scope: view.Scope}
			check("confirm-cleanup-and-sign-attestation", true)
			local.ComputedCandidateID = sum([]byte("computed-five-files"))
			local.CandidateResultID = sum([]byte("result-five-files"))
			local.CandidateAttemptID = attempt
			check("get-candidate-grant", false)
			local.Grant = &TurnGrantV4{AttemptID: attempt, ExpiresAt: now.Add(time.Hour)}
			check("upload-candidate", true)
			local.UploadedAttemptID = attempt
			local.UploadedArtifactID = local.CandidateResultID
			c.Deliveries[0].ContributionResultID = local.CandidateResultID
			check("wait-for-candidate-acceptance", false)
			c.Deliveries[0].Status = "retired"
			check("wait-for-replacement-attempt", false)
			replacement := strings.Repeat("cd", 16)
			c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: view.Scope, Kind: "candidate", AttemptID: replacement, Status: "allocated"})
			index.Turns[0].Allocations = append([]transcript.CandidateAllocationV4{{CheckpointSequence: 2, Checkpoint: allocationPairV4(2), AttemptID: replacement, AllocatedAt: now.Add(time.Minute).Format(time.RFC3339)}}, index.Turns[0].Allocations...)
			local.Grant = &TurnGrantV4{AttemptID: replacement, ExpiresAt: now.Add(time.Hour)}
			check("contribute", true)
			// A fresh computation under the replacement allocation can now be
			// uploaded and accepted; the retired candidate is never reused.
			local.CandidateAttemptID = replacement
			local.UploadedAttemptID = ""
			local.UploadedArtifactID = ""
			check("upload-candidate", true)
			c.Deliveries[0].Status = "rejected"
			c.Deliveries[0].ContributionResultID = local.CandidateResultID
			check("inspect-rejected-result", true)
			c.Deliveries[0].Status = "retired"
			c.Deliveries[0].ContributionResultID = ""
			c.Deliveries[1].Status = "accepted"
			c.Deliveries[1].ContributionResultID = local.CandidateResultID
			index.Turns[0].AcceptedChain = &transcript.AcceptedChainCommitmentV4{AttemptID: replacement, ContributionResultID: local.CandidateResultID}
			if phase == "phase1" {
				c.Progress.Phase1.AcceptedCount = 1
			} else {
				c.Progress.Phase2.AcceptedCount = 1
			}
			check("turn-complete", false)
		})
	}
}

func TestV4CoordinatorVerifiesSubmissionBeforeAnotherAction(t *testing.T) {
	_, p, c, index, enrollments, view := enrolledTurnV4(t, "phase1")
	now := time.Now().UTC()
	attempt := strings.Repeat("ab", 16)
	index.Turns = []transcript.TurnCommitmentV4{{Scope: view.Scope, Allocations: []transcript.CandidateAllocationV4{{CheckpointSequence: 1, Checkpoint: allocationPairV4(1), AttemptID: attempt, AllocatedAt: now.Format(time.RFC3339)}}}}
	c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: "candidate", AttemptID: attempt, Status: "allocated"}}
	local := LocalTurnV4{Scope: view.Scope}
	s := encodeTurnFixtureV4(t, c, index, enrollments)
	r, err := s.RecommendTurnV4(p, "phase1", Coordinator, "", local, attempt, now)
	if err != nil || r.Action != "download-and-check-candidate" {
		t.Fatal(r, err)
	}
	local.CandidateResultID = sum([]byte("incoming"))
	local.CandidateReceivedAttemptID = attempt
	r, err = s.RecommendTurnV4(p, "phase1", Coordinator, "", local, attempt, now)
	if err != nil || r.Action != "verify-and-accept-candidate" {
		t.Fatal(r, err)
	}
}

func TestV4PendingOperationKeepsItsOriginalScope(t *testing.T) {
	s, p, _, _, _ := turnFixtureV4(t, "phase1")
	old := transcript.ContributionScopeV4{CeremonyID: p.Definition.CeremonyID, Phase: "phase1", Index: 1, ParticipantID: "p1", ParentHeadID: sum([]byte("old"))}
	r, err := s.RecommendTurnV4(p, "phase1", Participant, "p2", LocalTurnV4{Scope: old, PendingOperation: true}, "", time.Now())
	if err != nil || r.Action != "inspect-retained-operation" || r.Scope != old {
		t.Fatal("interrupted operation scope was replaced", r, err)
	}
}
