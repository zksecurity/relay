package storagefirst

import (
	"fmt"
	"time"
)

type Role string

const (
	Coordinator Role = "coordinator"
	Participant Role = "participant"
)

type Action string

const (
	ActionOpenOutbound      Action = "open-outbound-turn"
	ActionDownloadOutbound  Action = "download-and-verify-outbound"
	ActionUploadReceipt     Action = "sign-and-upload-receipt"
	ActionWaitReceipt       Action = "wait-for-receipt"
	ActionAcceptReceipt     Action = "verify-and-accept-receipt"
	ActionIssueGrant        Action = "issue-candidate-grant"
	ActionWaitGrant         Action = "wait-for-candidate-grant"
	ActionContribute        Action = "contribute"
	ActionUploadCandidate   Action = "upload-candidate"
	ActionWaitCandidate     Action = "wait-for-candidate"
	ActionAcceptCandidate   Action = "verify-and-accept-candidate"
	ActionConfirmAcceptance Action = "confirm-exact-candidate-acceptance"
	ActionNextTurn          Action = "start-next-turn"
	ActionClosePhase        Action = "close-phase1"
)

type OperationKind string

const (
	OperationOutboundDownloaded OperationKind = "outbound-downloaded"
	OperationReceiptUploaded    OperationKind = "receipt-uploaded"
	OperationCandidateGrant     OperationKind = "candidate-grant-saved"
	OperationCandidateComputed  OperationKind = "candidate-computed"
	OperationCandidateUploaded  OperationKind = "candidate-uploaded"
)

type OperationFact struct {
	Kind             OperationKind `json:"kind"`
	CheckpointDigest string        `json:"checkpoint_digest"`
	Phase            string        `json:"phase"`
	Index            int           `json:"index"`
	IdentityID       string        `json:"identity_id"`
	AttemptID        string        `json:"attempt_id"`
	ArtifactDigest   string        `json:"artifact_digest"`
	GrantExpiresAt   string        `json:"grant_expires_at,omitempty"`
}

// LocalFacts contains exact durable operation results, never unscoped
// completion booleans.
type LocalFacts struct {
	Schema     string          `json:"schema"`
	Role       Role            `json:"role"`
	IdentityID string          `json:"identity_id"`
	Operations []OperationFact `json:"operations"`
}

// AuthenticatedObservedSubmission has no exported fields. A caller can obtain
// a usable value only through AuthenticateObservedSubmission, after proof-tool
// verifies the exact signed envelope, checkpoint slot, and bounded manifest.
type AuthenticatedObservedSubmission struct {
	ceremonyID       string
	checkpointDigest string
	slot             Slot
	manifestDigest   string
}

// ObservedObjects is an opaque set of proof-tool-authenticated submissions.
// Its zero value safely represents no observed submissions.
type ObservedObjects struct {
	submissions []AuthenticatedObservedSubmission
}

func ObservedSubmissions(values ...AuthenticatedObservedSubmission) ObservedObjects {
	return ObservedObjects{submissions: append([]AuthenticatedObservedSubmission(nil), values...)}
}

type Recommendation struct {
	Action Action
	Ready  bool
	Reason string
}

func RecommendPhase1(checkpoint Checkpoint, local LocalFacts, observed ObservedObjects) (Recommendation, error) {
	return RecommendPhase1At(checkpoint, local, observed, time.Now().UTC())
}

func RecommendPhase1At(checkpoint Checkpoint, local LocalFacts, observed ObservedObjects, now time.Time) (Recommendation, error) {
	if !checkpoint.authenticatedEvidence {
		return Recommendation{}, fmt.Errorf("Phase 1 guidance requires a fully evidence-verified checkpoint from storage sync")
	}
	if local.Role != Coordinator && local.Role != Participant {
		return Recommendation{}, fmt.Errorf("unsupported Phase 1 role %q", local.Role)
	}
	if err := validatePhase1Projection(checkpoint); err != nil {
		return Recommendation{}, err
	}
	if err := validateLocalFacts(local); err != nil {
		return Recommendation{}, err
	}
	stage := checkpoint.Transition
	if checkpoint.Position.Sequence == 0 {
		stage = "initial"
	}
	if local.Role == Coordinator {
		switch stage {
		case "initial":
			if checkpoint.Phase1Closed {
				return Recommendation{}, fmt.Errorf("initial checkpoint cannot have a closed phase")
			}
			return Recommendation{Action: ActionOpenOutbound, Ready: true, Reason: "open the next scheduled participant turn"}, nil
		case "phase1-candidate-accepted":
			if checkpoint.Phase1Closed {
				return Recommendation{Action: ActionClosePhase, Reason: "Phase 1 is already closed"}, nil
			}
			if checkpoint.Phase1Accepted >= checkpoint.Phase1ScheduledTotal {
				return Recommendation{Action: ActionClosePhase, Ready: true, Reason: "all scheduled Phase 1 participants have been accepted"}, nil
			}
			return Recommendation{Action: ActionNextTurn, Ready: true, Reason: "start the next authenticated scheduled participant turn"}, nil
		case "phase1-outbound-published":
			slot, ok := checkpoint.slot("receipt")
			if !ok {
				return Recommendation{}, fmt.Errorf("checkpoint has no exact receipt slot for the current turn")
			}
			if observed.matches(checkpoint, slot) {
				return Recommendation{Action: ActionAcceptReceipt, Ready: true, Reason: "the exact allocated receipt is available for verification"}, nil
			}
			return Recommendation{Action: ActionWaitReceipt, Reason: "waiting for the exact allocated receipt manifest"}, nil
		case "phase1-receipt-accepted":
			slot, ok := checkpoint.slot("candidate")
			if !ok {
				return Recommendation{}, fmt.Errorf("checkpoint has no exact candidate slot for the current turn")
			}
			if !local.has(OperationCandidateGrant, checkpoint, slot, "", now) {
				return Recommendation{Action: ActionIssueGrant, Ready: true, Reason: "receipt acceptance allocated the candidate attempt"}, nil
			}
			if observed.matches(checkpoint, slot) {
				return Recommendation{Action: ActionAcceptCandidate, Ready: true, Reason: "the exact allocated candidate is available for verification"}, nil
			}
			return Recommendation{Action: ActionWaitCandidate, Reason: "waiting for the exact allocated candidate manifest"}, nil
		default:
			return Recommendation{}, fmt.Errorf("unsupported checkpoint transition %q", stage)
		}
	}
	if checkpoint.ParticipantID != "" && checkpoint.ParticipantID != local.IdentityID {
		return Recommendation{Action: ActionWaitReceipt, Reason: "another participant is assigned to the current turn"}, nil
	}
	switch stage {
	case "initial":
		return Recommendation{Action: ActionDownloadOutbound, Reason: "the coordinator has not opened this turn yet"}, nil
	case "phase1-outbound-published":
		slot, ok := checkpoint.slot("receipt")
		if !ok {
			return Recommendation{}, fmt.Errorf("checkpoint has no exact receipt slot for the current turn")
		}
		if !local.has(OperationOutboundDownloaded, checkpoint, slot, "", now) {
			return Recommendation{Action: ActionDownloadOutbound, Ready: true, Reason: "download and authenticate the exact files named by the checkpoint"}, nil
		}
		if !local.has(OperationReceiptUploaded, checkpoint, slot, "", now) {
			return Recommendation{Action: ActionUploadReceipt, Ready: true, Reason: "confirm receipt before contribution is authorized"}, nil
		}
		return Recommendation{Action: ActionWaitGrant, Reason: "the exact receipt is uploaded but not yet accepted"}, nil
	case "phase1-receipt-accepted":
		slot, ok := checkpoint.slot("candidate")
		if !ok {
			return Recommendation{}, fmt.Errorf("checkpoint has no exact candidate slot for the current turn")
		}
		if !local.has(OperationCandidateGrant, checkpoint, slot, "", now) {
			return Recommendation{Action: ActionWaitGrant, Reason: "the coordinator must deliver an unexpired private grant for this exact attempt"}, nil
		}
		computed := local.fact(OperationCandidateComputed, checkpoint, slot, "", now)
		if computed == nil {
			return Recommendation{Action: ActionContribute, Ready: true, Reason: "receipt is accepted and the exact candidate grant is present"}, nil
		}
		if !local.has(OperationCandidateUploaded, checkpoint, slot, computed.ArtifactDigest, now) {
			return Recommendation{Action: ActionUploadCandidate, Ready: true, Reason: "resume the retained exact candidate upload without recomputing"}, nil
		}
		return Recommendation{Action: ActionConfirmAcceptance, Reason: "exact candidate uploaded; waiting for signed coordinator acceptance"}, nil
	case "phase1-candidate-accepted":
		accepted := checkpoint.AcceptedCandidate
		if accepted == nil || !accepted.valid() || accepted.IdentityID != local.IdentityID || !local.hasAcceptedUpload(*accepted) {
			return Recommendation{Action: ActionConfirmAcceptance, Reason: "acceptance names a different or unrecorded local candidate"}, nil
		}
		return Recommendation{Action: ActionConfirmAcceptance, Ready: true, Reason: "signed acceptance matches this exact attempt, candidate digest, head, and acknowledgement"}, nil
	default:
		return Recommendation{}, fmt.Errorf("unsupported checkpoint transition %q", stage)
	}
}

func validatePhase1Projection(checkpoint Checkpoint) error {
	if !validDigest(checkpoint.Position.Digest) {
		return fmt.Errorf("checkpoint projection has no authenticated digest")
	}
	if checkpoint.Phase1ScheduledTotal < 1 || checkpoint.Phase1ScheduledTotal > 255 ||
		checkpoint.Phase1Accepted < 0 || checkpoint.Phase1Accepted > checkpoint.Phase1ScheduledTotal {
		return fmt.Errorf("checkpoint projection has an invalid Phase 1 schedule position")
	}
	if checkpoint.Phase1Closed {
		if checkpoint.Phase1NextParticipantID != "" {
			return fmt.Errorf("closed Phase 1 projection still names a next participant")
		}
	} else if checkpoint.Phase1Accepted < checkpoint.Phase1ScheduledTotal && !validComponent(checkpoint.Phase1NextParticipantID) {
		return fmt.Errorf("open Phase 1 projection does not name the next scheduled participant")
	}
	if checkpoint.Transition == "phase1-candidate-accepted" && (checkpoint.AcceptedCandidate == nil || !checkpoint.AcceptedCandidate.valid()) {
		return fmt.Errorf("candidate-accepted checkpoint lacks an exact accepted-candidate projection")
	}
	return nil
}

func (c Checkpoint) slot(kind string) (Slot, bool) {
	for _, slot := range c.Slots {
		if slot.Kind == kind && slot.Phase == "phase1" && slot.Index == c.Phase1Accepted+1 && slot.IdentityID == c.ParticipantID {
			return slot, true
		}
	}
	return Slot{}, false
}

func (o ObservedObjects) matches(checkpoint Checkpoint, slot Slot) bool {
	for _, seen := range o.submissions {
		if seen.ceremonyID == checkpoint.CeremonyID && seen.checkpointDigest == checkpoint.Position.Digest &&
			seen.slot == slot && validDigest(seen.manifestDigest) {
			return true
		}
	}
	return false
}

func (l LocalFacts) fact(kind OperationKind, checkpoint Checkpoint, slot Slot, artifactDigest string, now time.Time) *OperationFact {
	for i := range l.Operations {
		fact := &l.Operations[i]
		if fact.Kind != kind || fact.CheckpointDigest != checkpoint.Position.Digest || fact.Phase != slot.Phase || fact.Index != slot.Index || fact.IdentityID != slot.IdentityID || fact.AttemptID != slot.AttemptID || (artifactDigest != "" && fact.ArtifactDigest != artifactDigest) {
			continue
		}
		if kind == OperationCandidateGrant {
			expires, _ := time.Parse(time.RFC3339, fact.GrantExpiresAt)
			if !expires.After(now.UTC()) {
				continue
			}
		}
		return fact
	}
	return nil
}

func (l LocalFacts) has(kind OperationKind, checkpoint Checkpoint, slot Slot, digest string, now time.Time) bool {
	return l.fact(kind, checkpoint, slot, digest, now) != nil
}

func (l LocalFacts) hasAcceptedUpload(accepted AcceptedCandidate) bool {
	for _, fact := range l.Operations {
		if fact.Kind == OperationCandidateUploaded && fact.CheckpointDigest == accepted.OperationCheckpointDigest && fact.Phase == "phase1" && fact.Index == accepted.Index && fact.IdentityID == accepted.IdentityID && fact.AttemptID == accepted.AttemptID && fact.ArtifactDigest == accepted.CandidateDigest {
			return true
		}
	}
	return false
}

func (a AcceptedCandidate) valid() bool {
	return validDigest(a.OperationCheckpointDigest) && validDigest(a.BasisCheckpointDigest) &&
		a.Index > 0 && a.Index <= 255 && validComponent(a.IdentityID) && validAttempt(a.AttemptID) &&
		validDigest(a.CandidateDigest) && validDigest(a.AcceptedHeadID) && validDigest(a.AcknowledgementDigest)
}
