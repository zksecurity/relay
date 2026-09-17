package storagefirst

import (
	"errors"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

type TurnGrantV4 struct {
	AttemptID string
	ExpiresAt time.Time
}

// LocalTurnV4 is reconstructed from this role's exact retained artifacts and
// operation journal. It is not a signature verifier or a publication authority.
// Artifacts bind Scope; grants and uploaded manifests additionally bind attempts.
// Callers inspect an interrupted operation instead of presenting empty facts.
// Participant inventory identities must be reconstructed together by proof-tool:
// cleanup completes the fixed five-file candidate inventory.
// These strings alone do not establish that relationship.
type LocalTurnV4 struct {
	Scope            transcript.ContributionScopeV4
	PendingOperation bool
	// GeneratedOutput is reconstructed by the three-file proof-tool inspection
	// only after reconciling the original contributor container's absence.
	// It does not establish cleanup confirmation or authorize uploading.
	GeneratedOutput    *transcript.ComputationOutputFactsV4
	CandidateInventory *transcript.ContributionInventoryFactsV4
	// CandidateAttemptID is the signed allocation under which the retained
	// candidate was computed. It cannot move to a later allocation: proof-tool
	// verifies that allocation precedes its contribution.
	CandidateAttemptID         string
	ComputedCandidateID        string
	CandidateResultID          string
	CandidateReceivedAttemptID string
	Grant                      *TurnGrantV4
	UploadedAttemptID          string
	UploadedArtifactID         string
}

type TurnRecommendationV4 struct {
	Action    string
	Ready     bool
	Reason    string
	Scope     transcript.ContributionScopeV4
	AttemptID string
}

// RecommendTurnV4 does not execute work. Before any consequential action the
// caller re-syncs and verifies artifacts/grants; checkpoint proposals remain
// bound to their exact predecessor and conditional root version.
func (s SnapshotV4) RecommendTurnV4(protocol transcript.DefinitionProtocol, phase string, role Role, identity string, local LocalTurnV4, observedAttempt string, now time.Time) (TurnRecommendationV4, error) {
	if role != Coordinator && role != Participant {
		return TurnRecommendationV4{}, errors.New("unsupported turn role")
	}
	if role == Participant && identity == "" {
		return TurnRecommendationV4{}, errors.New("participant identity required")
	}
	if role == Coordinator && identity != "" {
		return TurnRecommendationV4{}, errors.New("coordinator turn selector must not override participant")
	}
	view, err := s.TurnV4(protocol, phase, identity)
	if err != nil {
		return TurnRecommendationV4{}, err
	}
	r := TurnRecommendationV4{Scope: view.Scope}
	answer := func(action string, ready bool, reason string) (TurnRecommendationV4, error) {
		r.Action, r.Ready, r.Reason = action, ready, reason
		return r, nil
	}
	if local.PendingOperation {
		r.Scope = local.Scope // Inspect the retained operation, even if the backend moved on.
		return answer("inspect-retained-operation", true, "Inspect the interrupted operation before preparing new work.")
	}
	switch view.Stage {
	case TurnTerminalV4:
		return answer("ceremony-stopped", false, "The signed ceremony state stops further contributions.")
	case TurnPhaseNotStartedV4:
		return answer("wait-for-phase", false, "The coordinator has not initialized this phase.")
	case TurnWaitingV4:
		return answer("wait-for-your-turn", false, "An earlier scheduled participant must finish first.")
	case TurnPhaseClosedV4, TurnPhaseCompleteV4:
		return answer("phase-follow-up-not-connected", false, "This phase has no open participant turn; the V4 next-area workflow is not connected yet.")
	}
	if local.Scope != (transcript.ContributionScopeV4{}) && local.Scope != view.Scope {
		return TurnRecommendationV4{}, errors.New("retained work belongs to another turn; select its exact scope before proceeding")
	}
	for _, digest := range []string{local.ComputedCandidateID, local.CandidateResultID, local.UploadedArtifactID} {
		if digest != "" && !validDigest(digest) {
			return TurnRecommendationV4{}, errors.New("invalid retained artifact identity")
		}
	}
	if local.Scope == (transcript.ContributionScopeV4{}) && (local.GeneratedOutput != nil || local.CandidateInventory != nil || local.CandidateAttemptID != "" || local.ComputedCandidateID != "" || local.CandidateResultID != "" || local.Grant != nil || local.UploadedAttemptID != "") {
		return TurnRecommendationV4{}, errors.New("retained work has no exact turn scope")
	}
	if local.GeneratedOutput != nil && local.GeneratedOutput.Scope != view.Scope {
		return TurnRecommendationV4{}, errors.New("generated output belongs to another turn")
	}
	if local.CandidateInventory != nil && (local.CandidateInventory.Scope != view.Scope || local.CandidateInventory.ComputedCandidateID != local.ComputedCandidateID || local.CandidateInventory.CandidateResultID != local.CandidateResultID || (role == Participant && !validAttempt(local.CandidateAttemptID))) {
		return TurnRecommendationV4{}, errors.New("completed candidate inventory differs from retained turn facts")
	}
	if local.UploadedAttemptID != "" && !validAttempt(local.UploadedAttemptID) {
		return TurnRecommendationV4{}, errors.New("invalid retained upload attempt")
	}
	if local.CandidateReceivedAttemptID != "" && (!validAttempt(local.CandidateReceivedAttemptID) || local.CandidateResultID == "") {
		return answer("inspect-retained-operation", true, "A received-candidate record is incomplete. Inspect it before continuing.")
	}
	if local.Grant != nil && (!validAttempt(local.Grant.AttemptID) || local.Grant.ExpiresAt.IsZero()) {
		return TurnRecommendationV4{}, errors.New("invalid retained grant")
	}
	if observedAttempt != "" && !validAttempt(observedAttempt) {
		return TurnRecommendationV4{}, errors.New("invalid observed submission attempt")
	}
	if (local.UploadedAttemptID == "") != (local.UploadedArtifactID == "") {
		return TurnRecommendationV4{}, errors.New("inconsistent retained artifact bindings")
	}
	if role == Participant && local.CandidateResultID != "" && local.ComputedCandidateID == "" {
		return answer("inspect-retained-operation", true, "The completed upload package has no verified computation inventory. Inspect its exact files before continuing.")
	}
	c, err := s.State()
	if err != nil {
		return TurnRecommendationV4{}, err
	}
	if local.UploadedAttemptID != "" {
		matched := false
		for _, delivery := range c.Deliveries {
			if delivery.Scope != view.Scope || delivery.AttemptID != local.UploadedAttemptID {
				continue
			}
			matched = delivery.Kind == "candidate" && local.CandidateResultID != "" && local.UploadedArtifactID == local.CandidateResultID
		}
		if !matched {
			return answer("inspect-retained-operation", true, "A recorded upload has no matching retained artifact and exact delivery attempt. Inspect existing work before signing or computing again.")
		}
	}
	if local.CandidateResultID != "" && view.Stage != TurnAcceptedV4 {
		for _, prior := range c.Deliveries {
			if prior.Scope == view.Scope && prior.Status == "rejected" && prior.ContributionResultID == local.CandidateResultID {
				return answer("inspect-rejected-result", true, "This exact result was rejected. Do not upload it on a replacement attempt or recompute automatically.")
			}
		}
	}
	if role == Participant && local.GeneratedOutput != nil && local.ComputedCandidateID == "" && (view.Stage == TurnCandidateV4 || view.Stage == TurnReallocateV4) {
		return answer("confirm-cleanup-and-sign-attestation", true, "Computation output is verified. Check container cleanup and confirm your precautions before signing the cleanup statement; do not contribute again.")
	}
	switch view.Stage {
	case TurnEnrollmentV4:
		if role == Coordinator {
			return answer("collect-participant-enrollment", true, "Receive and verify this scheduled participant's signed enrollment.")
		}
		return answer("submit-your-enrollment", true, "Send your signed enrollment through the ceremony submission service.")
	case TurnAllocationV4:
		if role == Coordinator {
			return answer("allocate-candidate-attempt", true, "Allocate one candidate attempt for this exact participant, phase, turn and current head.")
		}
		return answer("wait-for-candidate-allocation", false, "The coordinator must publish your signed candidate allocation.")
	case TurnAcceptedV4:
		if local.CandidateResultID == "" {
			return answer("inspect-accepted-result", true, "The coordinator accepted this turn; recover and verify the exact result before marking local work complete.")
		}
		if local.CandidateResultID != view.Commitment.AcceptedChain.ContributionResultID {
			return answer("inspect-different-accepted-result", true, "The accepted result differs from your retained candidate. Do not upload it again.")
		}
		return answer("turn-complete", false, "The coordinator's accepted result matches your exact retained contribution.")
	case TurnReallocateV4:
		if role == Coordinator {
			return answer("allocate-replacement-attempt", true, "No active upload attempt remains; review retained work before allocating a replacement.")
		}
		return answer("wait-for-replacement-attempt", false, "Keep any completed candidate; the coordinator must allocate a replacement transport attempt.")
	}
	slot := view.CandidateAttempt
	if slot == nil {
		return TurnRecommendationV4{}, errors.New("turn has no supported active attempt")
	}
	r.AttemptID = slot.AttemptID
	grantReady := local.Grant != nil && local.Grant.AttemptID == slot.AttemptID && !now.IsZero() && local.Grant.ExpiresAt.After(now)
	if role == Coordinator {
		if observedAttempt == slot.AttemptID {
			if local.CandidateResultID == "" || local.CandidateReceivedAttemptID != slot.AttemptID {
				return answer("download-and-check-candidate", true, "Download the exact five-file candidate and verify its signed inventory.")
			}
			return answer("verify-and-accept-candidate", true, "Replay and verify this exact candidate, then conditionally publish its signed acceptance checkpoint.")
		}
		if !grantReady {
			return answer("issue-candidate-grant", true, "Issue or renew upload access for this exact active candidate attempt.")
		}
		return answer("wait-for-candidate", false, "Waiting for the candidate manifest; upload alone will not mean acceptance.")
	}
	if local.ComputedCandidateID == "" {
		return answer("contribute", true, "The signed allocation authorizes this exact turn. Proof-tool will recheck it and the complete input snapshot before generating randomness.")
	}
	if role == Participant && local.CandidateAttemptID != slot.AttemptID {
		return answer("contribute", true, "Your retained candidate belongs to a retired allocation. Preserve it for investigation; this replacement allocation requires a fresh contribution and cleanup statement.")
	}
	if local.UploadedAttemptID == slot.AttemptID && local.UploadedArtifactID == local.CandidateResultID {
		return answer("wait-for-candidate-acceptance", false, "Candidate manifest uploaded; wait for the coordinator's exact signed result.")
	}
	if local.CandidateResultID == "" {
		return answer("confirm-cleanup-and-sign-attestation", true, "Verify cleanup and complete the fixed five-file candidate; do not recompute.")
	}
	if !grantReady {
		return answer("get-candidate-grant", false, "Keep the completed candidate and return packet; obtain current upload access.")
	}
	return answer("upload-candidate", true, "Upload the retained five-file candidate, then publish its manifest last without recomputing.")
}
