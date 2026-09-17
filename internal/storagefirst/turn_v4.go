package storagefirst

import (
	"errors"
	"fmt"

	"github.com/zksecurity/relay/internal/transcript"
)

// TurnViewV4 is a backend-derived view, not permission to compute or publish.
// Local artifacts, current grants and mutation recovery are checked separately.
type TurnViewV4 struct {
	Stage            string
	Scope            transcript.ContributionScopeV4
	Commitment       *transcript.TurnCommitmentV4
	ReceiptAttempt   *transcript.DeliverySlotV4 // receipt-era development state; never populated by released V4
	CandidateAttempt *transcript.DeliverySlotV4
}

const (
	TurnPhaseNotStartedV4 = "phase-not-started"
	TurnWaitingV4         = "waiting-for-earlier-participant"
	TurnEnrollmentV4      = "participant-enrollment-needed"
	TurnAllocationV4      = "candidate-allocation-needed"
	TurnReceiptV4         = "receipt-era-state-not-supported"
	TurnCandidateV4       = "candidate-needed"
	TurnReallocateV4      = "replacement-attempt-needed"
	TurnAcceptedV4        = "accepted-result"
	TurnPhaseClosedV4     = "phase-closed"
	TurnPhaseCompleteV4   = "scheduled-turns-complete"
	TurnTerminalV4        = "ceremony-stopped"
)

// TurnV4 derives a turn from authenticated progress and commitments rather than
// the latest checkpoint event. An empty participant selects the coordinator's
// current turn. A named participant always sees its own position, even when
// another participant now owns the current turn. No legacy fallback occurs.
func (s SnapshotV4) TurnV4(protocol transcript.DefinitionProtocol, phase, participant string) (TurnViewV4, error) {
	c, err := s.State()
	if err != nil {
		return TurnViewV4{}, err
	}
	if !protocol.UsesV4() || protocol.Definition.CeremonyID != c.CeremonyID {
		return TurnViewV4{}, errors.New("turn guidance requires the matching authenticated V4 definition")
	}
	index, err := s.Commitments()
	if err != nil {
		return TurnViewV4{}, err
	}
	enrollments, err := s.Enrollments()
	if err != nil {
		return TurnViewV4{}, err
	}
	d := protocol.Definition
	schedule, err := d.Schedule(phase)
	if err != nil {
		return TurnViewV4{}, err
	}
	if len(schedule) == 0 || len(schedule) > 20 {
		return TurnViewV4{}, errors.New("invalid authenticated turn schedule")
	}
	seen := map[string]bool{}
	for _, id := range schedule {
		if id == "" || seen[id] {
			return TurnViewV4{}, errors.New("ambiguous authenticated turn schedule")
		}
		seen[id] = true
	}
	position := 0
	if participant != "" {
		position, err = d.SlotOf(phase, participant)
		if err != nil {
			return TurnViewV4{}, err
		}
	}
	if c.Progress.Terminal != nil {
		return TurnViewV4{Stage: TurnTerminalV4}, nil
	}
	var progress *transcript.CheckpointPhaseState
	var closure *transcript.SignedArtifactRefs
	if phase == "phase1" {
		progress = &c.Progress.Phase1
		closure = c.Progress.Phase1Closure
	} else {
		progress = c.Progress.Phase2
		closure = c.Progress.Phase2Closure
	}
	if progress == nil {
		return TurnViewV4{Stage: TurnPhaseNotStartedV4}, nil
	}
	accepted := int(progress.AcceptedCount)
	if accepted > len(schedule) {
		return TurnViewV4{}, errors.New("accepted count exceeds authenticated schedule")
	}
	if position == 0 {
		position = accepted + 1
	}
	if position > len(schedule) {
		return TurnViewV4{Stage: TurnPhaseCompleteV4}, nil
	}
	view := TurnViewV4{Scope: transcript.ContributionScopeV4{CeremonyID: c.CeremonyID, Phase: phase, Index: uint8(position), ParticipantID: schedule[position-1]}}
	for _, turn := range index.Turns {
		if turn.Scope.Phase == phase && int(turn.Scope.Index) == position {
			if view.Commitment != nil || turn.Scope.CeremonyID != c.CeremonyID || turn.Scope.ParticipantID != view.Scope.ParticipantID {
				return TurnViewV4{}, errors.New("turn commitment differs from authenticated schedule")
			}
			copy := turn
			view.Commitment = &copy
			view.Scope = turn.Scope
		}
	}
	if position <= accepted {
		if view.Commitment == nil || view.Commitment.AcceptedChain == nil {
			return TurnViewV4{}, errors.New("accepted turn has no exact chain/result commitment")
		}
		view.Stage = TurnAcceptedV4
		return view, nil
	}
	if closure != nil {
		view.Stage = TurnPhaseClosedV4
		return view, nil
	}
	if position > accepted+1 {
		view.Stage = TurnWaitingV4
		return view, nil
	}
	if view.Commitment != nil && view.Scope.ParentHeadID != progress.HeadRecordID {
		return TurnViewV4{}, errors.New("current turn has a different predecessor")
	}
	view.Scope.ParentHeadID = progress.HeadRecordID
	for _, slot := range c.Deliveries {
		if slot.Scope != view.Scope || slot.Status != "allocated" {
			continue
		}
		copy := slot
		if slot.Kind != "candidate" {
			return TurnViewV4{}, fmt.Errorf("unknown active delivery kind %q", slot.Kind)
		}
		if view.CandidateAttempt != nil {
			return TurnViewV4{}, errors.New("multiple active candidate attempts")
		}
		view.CandidateAttempt = &copy
	}
	// Outbound authoring requires this participant's enrollment, not completion
	// of the entire final-evidence roster. Other enrollments remain parallel work.
	journey, err := d.RequireJourney()
	if err != nil {
		return TurnViewV4{}, err
	}
	var expected *transcript.ExpectedEnrollment
	for _, e := range journey.RequiredEnrollments {
		if e.Role == "participant" && e.Identity.ID == view.Scope.ParticipantID {
			copy := e
			expected = &copy
		}
	}
	if expected == nil {
		return TurnViewV4{}, errors.New("scheduled participant missing from required enrollment projection")
	}
	view.Stage = TurnEnrollmentV4
	for _, item := range enrollments.Enrollments {
		e := item.Enrollment
		if e.Role == expected.Role && e.RoleIndex == expected.RoleIndex && e.Identity == expected.Identity {
			view.Stage = TurnAllocationV4
			break
		}
	}
	if view.Stage == TurnEnrollmentV4 {
		return view, nil
	}
	if view.CandidateAttempt != nil {
		view.Stage = TurnCandidateV4
		return view, nil
	}
	if view.Commitment != nil && len(view.Commitment.Allocations) > 0 {
		view.Stage = TurnReallocateV4
	}
	return view, nil
}
