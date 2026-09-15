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
type LocalTurnV4 struct {
	Scope                      transcript.ContributionScopeV4
	PendingOperation           bool
	OutboundSHA256             string
	ReceiptSHA256              string
	ReceiptHandoffSHA256       string
	CandidateResultID          string
	CandidateReceivedAttemptID string
	ReturnHandoffResultID      string
	ReturnReceiptResultID      string
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
	Outbound  *transcript.SignedArtifactRefs
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
	for _, digest := range []string{local.OutboundSHA256, local.ReceiptSHA256, local.ReceiptHandoffSHA256, local.CandidateResultID, local.ReturnHandoffResultID, local.ReturnReceiptResultID, local.UploadedArtifactID} {
		if digest != "" && !validDigest(digest) {
			return TurnRecommendationV4{}, errors.New("invalid retained artifact identity")
		}
	}
	if local.Scope == (transcript.ContributionScopeV4{}) && (local.OutboundSHA256 != "" || local.ReceiptSHA256 != "" || local.CandidateResultID != "" || local.Grant != nil || local.UploadedAttemptID != "") {
		return TurnRecommendationV4{}, errors.New("retained work has no exact turn scope")
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
	if (local.ReceiptSHA256 == "") != (local.ReceiptHandoffSHA256 == "") || (local.UploadedAttemptID == "") != (local.UploadedArtifactID == "") || (local.ReturnHandoffResultID != "" && local.ReturnHandoffResultID != local.CandidateResultID) || (local.ReturnReceiptResultID != "" && local.ReturnReceiptResultID != local.CandidateResultID) {
		return TurnRecommendationV4{}, errors.New("inconsistent retained artifact bindings")
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
			matched = (delivery.Kind == "receipt" && local.ReceiptSHA256 != "" && local.UploadedArtifactID == local.ReceiptSHA256) || (delivery.Kind == "candidate" && local.CandidateResultID != "" && local.UploadedArtifactID == local.CandidateResultID)
		}
		if !matched {
			return answer("inspect-retained-operation", true, "A recorded upload has no matching retained artifact and exact delivery attempt. Inspect existing work before signing or computing again.")
		}
	}
	if local.CandidateResultID != "" && (view.Commitment == nil || view.Commitment.InputReceipt == nil) {
		return answer("inspect-retained-operation", true, "A retained candidate has no accepted input receipt in this state. Inspect it; do not recompute or upload.")
	}
	if local.CandidateResultID != "" && view.Stage != TurnAcceptedV4 {
		for _, prior := range c.Deliveries {
			if prior.Scope == view.Scope && prior.Status == "rejected" && prior.ContributionResultID == local.CandidateResultID {
				return answer("inspect-rejected-result", true, "This exact result was rejected. Do not upload it on a replacement attempt or recompute automatically.")
			}
		}
	}
	switch view.Stage {
	case TurnEnrollmentV4:
		if role == Coordinator {
			return answer("collect-participant-enrollment", true, "Receive and verify this scheduled participant's signed enrollment.")
		}
		return answer("submit-your-enrollment", true, "Send your signed enrollment through the ceremony submission service.")
	case TurnOutboundV4:
		if role == Coordinator {
			return answer("prepare-and-publish-outbound", true, "Prepare and sign the input packet for this exact turn.")
		}
		return answer("wait-for-input-packet", false, "The coordinator must publish your signed input packet.")
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
		return answer("wait-for-replacement-attempt", false, "Keep your existing signed files; the coordinator must allocate replacement upload access.")
	}
	var slot *transcript.DeliverySlotV4
	if view.Stage == TurnReceiptV4 {
		slot = view.ReceiptAttempt
	} else if view.Stage == TurnCandidateV4 {
		slot = view.CandidateAttempt
	}
	if slot == nil {
		return TurnRecommendationV4{}, errors.New("turn has no supported active attempt")
	}
	r.AttemptID = slot.AttemptID
	grantReady := local.Grant != nil && local.Grant.AttemptID == slot.AttemptID && !now.IsZero() && local.Grant.ExpiresAt.After(now)
	if role == Coordinator {
		if observedAttempt == slot.AttemptID {
			if slot.Kind == "candidate" {
				if local.CandidateResultID == "" || local.CandidateReceivedAttemptID != slot.AttemptID {
					return answer("download-and-check-candidate", true, "Download the exact submitted candidate and verify its inventory and signed return packet.")
				}
				if local.ReturnReceiptResultID != local.CandidateResultID {
					return answer("prepare-and-sign-return-receipt", true, "Verify the received candidate files and sign the coordinator return receipt before acceptance.")
				}
			}
			return answer("verify-and-accept-"+slot.Kind, true, "Download and verify this exact submission before signing acceptance.")
		}
		if !grantReady {
			return answer("issue-"+slot.Kind+"-grant", true, "Issue or renew access for this exact active upload attempt.")
		}
		return answer("wait-for-"+slot.Kind, false, "Waiting for the allocated submission; upload alone will not mean acceptance.")
	}
	if view.Stage == TurnReceiptV4 {
		outbound := view.Commitment.Outbounds[0].Pair
		if local.ReceiptSHA256 != "" {
			found := false
			for _, entry := range view.Commitment.Outbounds {
				if entry.Pair.Record.Digest.SHA256 == local.ReceiptHandoffSHA256 {
					outbound = entry.Pair
					found = true
					break
				}
			}
			if !found {
				return TurnRecommendationV4{}, errors.New("retained receipt acknowledges an uncommitted input packet")
			}
		}
		r.Outbound = &outbound
		if local.ReceiptSHA256 == "" {
			if local.OutboundSHA256 != outbound.Record.Digest.SHA256 {
				return answer("download-and-verify-outbound", true, "Download the signed input packet and every public file it names.")
			}
			return answer("prepare-and-sign-receipt", true, "Verify the retained input files and sign your receipt.")
		}
		if local.UploadedAttemptID == slot.AttemptID && local.UploadedArtifactID == local.ReceiptSHA256 {
			return answer("wait-for-receipt-acceptance", false, "Receipt uploaded; wait for signed coordinator acceptance before computation.")
		}
		if !grantReady {
			return answer("get-receipt-grant", false, "Obtain current upload access for this receipt attempt; keep your signed receipt.")
		}
		return answer("upload-receipt", true, "Upload the exact signed receipt to the active attempt.")
	}
	if local.CandidateResultID == "" {
		if !grantReady {
			return answer("get-candidate-grant", false, "Receipt acceptance is verified; obtain upload access for the active candidate attempt.")
		}
		return answer("contribute", true, "Signed receipt acceptance and current upload access are present. Confirm before starting isolated computation.")
	}
	if local.UploadedAttemptID == slot.AttemptID && local.UploadedArtifactID == local.CandidateResultID {
		return answer("wait-for-candidate-acceptance", false, "Candidate uploaded; wait for the coordinator's exact signed result.")
	}
	if local.ReturnHandoffResultID != local.CandidateResultID {
		return answer("prepare-and-sign-return-handoff", true, "Prepare the return packet for this exact completed candidate; do not recompute.")
	}
	if !grantReady {
		return answer("get-candidate-grant", false, "Keep the completed candidate and return packet; obtain current upload access.")
	}
	return answer("upload-candidate", true, "Upload the retained candidate and signed return packet without recomputing.")
}
