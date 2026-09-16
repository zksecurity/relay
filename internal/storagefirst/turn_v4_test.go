package storagefirst

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

// Fixtures are already-verified projection data, not a cryptographic test.
func turnFixtureV4(t *testing.T, phase string) (SnapshotV4, transcript.DefinitionProtocol, transcript.CheckpointStateV4, transcript.CheckpointCommitmentsV4, transcript.EnrollmentMetadataV4) {
	t.Helper()
	id := sum([]byte("ceremony"))
	head := sum([]byte("head"))
	d := transcript.Definition{CeremonyID: id, Phase1Participants: []string{"p1", "p2"}, Phase2Participants: []string{"p2", "p1"}, Journey: &transcript.DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v2", ObserverRequirementSource: "signed policy"}}
	for _, entry := range []struct {
		role, id string
		index    int
	}{{"coordinator", "coord", 1}, {"release-signer", "signer", 1}, {"participant", "p1", 1}, {"participant", "p2", 2}} {
		d.Journey.RequiredEnrollments = append(d.Journey.RequiredEnrollments, transcript.ExpectedEnrollment{Role: entry.role, RoleIndex: entry.index, Identity: transcript.PublicIdentity{ID: entry.id, KeyID: "key-" + entry.id, PublicKeyFingerprint: "fingerprint-" + entry.id}})
	}
	p := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v4", StorageWorkflow: "storage-first-v2", ReleaseVerification: "coordinator-full-replay-v1", Definition: d}
	c := transcript.CheckpointStateV4{CeremonyID: id, Deliveries: []transcript.DeliverySlotV4{}, Progress: transcript.CheckpointProgressV4{Phase1: transcript.CheckpointPhaseState{Phase: "phase1", HeadRecordID: head}}}
	if phase == "phase2" {
		c.Progress.Phase2 = &transcript.CheckpointPhaseState{Phase: "phase2", HeadRecordID: head}
	}
	index := transcript.CheckpointCommitmentsV4{Enrollments: []transcript.SignedArtifactRefs{}, Turns: []transcript.TurnCommitmentV4{}}
	e := transcript.EnrollmentMetadataV4{CeremonyID: id, Enrollments: []transcript.CommittedEnrollmentMetadataV4{}}
	return encodeTurnFixtureV4(t, c, index, e), p, c, index, e
}

func encodeTurnFixtureV4(t *testing.T, c transcript.CheckpointStateV4, index transcript.CheckpointCommitmentsV4, e transcript.EnrollmentMetadataV4) SnapshotV4 {
	t.Helper()
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return SnapshotV4{inspection: encode(c), commitments: encode(index), enrollments: encode(e)}
}

func TestTurnV4BothPhasesUseProgressNotLatestEvent(t *testing.T) {
	for _, phase := range []string{"phase1", "phase2"} {
		t.Run(phase, func(t *testing.T) {
			_, p, c, index, e := turnFixtureV4(t, phase)
			schedule, _ := p.Definition.Schedule(phase)
			who := schedule[0]
			check := func(want string) {
				t.Helper()
				s := encodeTurnFixtureV4(t, c, index, e)
				for _, actor := range []string{"", who} {
					v, err := s.TurnV4(p, phase, actor)
					if err != nil || v.Stage != want {
						t.Fatalf("actor %q got %+v %v want %s", actor, v, err, want)
					}
				}
			}
			check(TurnEnrollmentV4)
			for _, required := range p.Definition.Journey.RequiredEnrollments {
				if required.Identity.ID == who {
					e.Enrollments = append(e.Enrollments, transcript.CommittedEnrollmentMetadataV4{Enrollment: transcript.EnrollmentInspection{Role: required.Role, RoleIndex: required.RoleIndex, Identity: required.Identity}})
				}
			}
			check(TurnAllocationV4) // Other required enrollments deliberately absent.
			view, err := encodeTurnFixtureV4(t, c, index, e).TurnV4(p, phase, who)
			if err != nil {
				t.Fatal(err)
			}
			candidateAttempt := strings.Repeat("cd", 16)
			turn := transcript.TurnCommitmentV4{Scope: view.Scope, Allocations: []transcript.CandidateAllocationV4{{CheckpointSequence: 1, AttemptID: candidateAttempt, AllocatedAt: "2026-09-16T00:00:00Z"}}}
			index.Turns = []transcript.TurnCommitmentV4{turn}
			c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: "candidate", AttemptID: candidateAttempt, Status: "allocated"}}
			check(TurnCandidateV4)
			c.Sequence += 4 // Unrelated committed evidence does not change this turn.
			check(TurnCandidateV4)
			c.Deliveries[0].Status = "retired"
			check(TurnReallocateV4)
			replacement := strings.Repeat("ef", 16)
			c.Deliveries = append(c.Deliveries, transcript.DeliverySlotV4{Scope: view.Scope, Kind: "candidate", AttemptID: replacement, Status: "allocated"})
			index.Turns[0].Allocations = append([]transcript.CandidateAllocationV4{{CheckpointSequence: c.Sequence, AttemptID: replacement, AllocatedAt: "2026-09-16T00:01:00Z"}}, index.Turns[0].Allocations...)
			check(TurnCandidateV4)
			result := sum([]byte("result"))
			c.Deliveries[1].Status = "accepted"
			c.Deliveries[1].ContributionResultID = result
			index.Turns[0].AcceptedChain = &transcript.AcceptedChainCommitmentV4{AttemptID: replacement, ContributionResultID: result}
			if phase == "phase1" {
				c.Progress.Phase1.AcceptedCount = 1
				c.Progress.Phase1.HeadRecordID = sum([]byte("next"))
			} else {
				c.Progress.Phase2.AcceptedCount = 1
				c.Progress.Phase2.HeadRecordID = sum([]byte("next"))
			}
			v, err := encodeTurnFixtureV4(t, c, index, e).TurnV4(p, phase, who)
			if err != nil || v.Stage != TurnAcceptedV4 || v.Scope != view.Scope {
				t.Fatal("earlier participant lost accepted result", v, err)
			}
			v, err = encodeTurnFixtureV4(t, c, index, e).TurnV4(p, phase, "")
			if err != nil || v.Stage != TurnEnrollmentV4 || v.Scope.ParticipantID != schedule[1] {
				t.Fatal("coordinator did not move to next participant", v, err)
			}
		})
	}
}

func TestTurnV4NoLegacyFallbackOrPrematureTurn(t *testing.T) {
	s, p, c, index, e := turnFixtureV4(t, "phase1")
	if _, err := (SnapshotV4{}).TurnV4(p, "phase1", ""); err == nil {
		t.Fatal("empty snapshot usable")
	}
	if v, err := s.TurnV4(p, "phase2", "p1"); err != nil || v.Stage != TurnPhaseNotStartedV4 {
		t.Fatal(v, err)
	}
	if v, err := s.TurnV4(p, "phase1", "p2"); err != nil || v.Stage != TurnWaitingV4 {
		t.Fatal(v, err)
	}
	if _, err := s.TurnV4(p, "phase1", "stranger"); err == nil {
		t.Fatal("unassigned participant accepted")
	}
	bad := p
	bad.DefinitionSchema = "proof-tool-mpc-ceremony-definition-v3"
	if _, err := s.TurnV4(bad, "phase1", ""); err == nil {
		t.Fatal("legacy fallback")
	}
	c.Progress.Phase1Closure = &transcript.SignedArtifactRefs{}
	if v, err := encodeTurnFixtureV4(t, c, index, e).TurnV4(p, "phase1", ""); err != nil || v.Stage != TurnPhaseClosedV4 {
		t.Fatal(v, err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"abort","record":{}}`), &c.Progress.Terminal); err != nil {
		t.Fatal(err)
	}
	if v, err := encodeTurnFixtureV4(t, c, index, e).TurnV4(p, "phase1", "p1"); err != nil || v.Stage != TurnTerminalV4 {
		t.Fatal(v, err)
	}
}
