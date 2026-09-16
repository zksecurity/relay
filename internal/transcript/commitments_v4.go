package transcript

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Commitments locate signed records in verified checkpoint ancestry. They do
// not assert those record contents or their named payloads were verified.
type CheckpointCommitmentsV4 struct {
	Enrollments           []SignedArtifactRefs `json:"enrollments"`
	Turns                 []TurnCommitmentV4   `json:"turns"`
	FinalReleaseArtifacts []ArtifactRef        `json:"final_release_artifacts"`
}

type CandidateAllocationV4 struct {
	CheckpointSequence uint64             `json:"checkpoint_sequence"`
	Checkpoint         SignedArtifactRefs `json:"checkpoint"`
	AttemptID          string             `json:"attempt_id"`
	AllocatedAt        string             `json:"allocated_at"`
}

// Receipt-era fields are retained only so an interrupted development build can
// be inspected. The released V4 validator below rejects them.
type OutboundCommitmentV4 struct {
	CheckpointSequence uint64             `json:"checkpoint_sequence"`
	PublishedAttemptID string             `json:"published_attempt_id"`
	Pair               SignedArtifactRefs `json:"pair"`
}

type AcceptedTurnRecordV4 struct {
	AttemptID string             `json:"attempt_id"`
	Pair      SignedArtifactRefs `json:"pair"`
}

type AcceptedChainCommitmentV4 struct {
	AttemptID            string             `json:"attempt_id"`
	ContributionResultID string             `json:"contribution_result_id"`
	Pair                 SignedArtifactRefs `json:"pair"`
}

type TurnCommitmentV4 struct {
	Scope ContributionScopeV4 `json:"scope"`
	// Newest first. Retired attempts remain visible, while only one matching
	// delivery slot may be active.
	Allocations   []CandidateAllocationV4    `json:"allocations"`
	AcceptedChain *AcceptedChainCommitmentV4 `json:"accepted_chain,omitempty"`
	Outbounds     []OutboundCommitmentV4     `json:"outbounds,omitempty"`
	InputReceipt  *AcceptedTurnRecordV4      `json:"input_receipt,omitempty"`
	ReturnHandoff *SignedArtifactRefs        `json:"return_handoff,omitempty"`
	ReturnReceipt *SignedArtifactRefs        `json:"return_receipt,omitempty"`
}

func validateCommitmentsV4(c CheckpointStateV4, index CheckpointCommitmentsV4) error {
	if index.Enrollments == nil || len(index.Enrollments) > 128 || index.Turns == nil || len(index.Turns) > 40 || len(index.FinalReleaseArtifacts) > 2053 {
		return errors.New("missing or oversized commitment index")
	}
	if (c.Progress.FinalRelease != nil) != (len(index.FinalReleaseArtifacts) != 0) {
		return errors.New("final release download inventory does not match ceremony progress")
	}
	lastArtifact := ""
	for _, ref := range index.FinalReleaseArtifacts {
		if !strings.HasPrefix(ref.Name, "final/release/") {
			return errors.New("final release download inventory escapes its namespace")
		}
		if err := validateBoundedRefV4(ref, 16<<30); err != nil {
			return err
		}
		if ref.Name <= lastArtifact {
			return errors.New("final release download inventory must be sorted and unique")
		}
		lastArtifact = ref.Name
	}
	last := ""
	for _, pair := range index.Enrollments {
		if err := validatePairV4(pair); err != nil {
			return err
		}
		if pair.Record.Name <= last {
			return errors.New("unordered or duplicate enrollment commitment")
		}
		last = pair.Record.Name
	}
	last = ""
	for _, turn := range index.Turns {
		if len(turn.Outbounds) != 0 || turn.InputReceipt != nil || turn.ReturnHandoff != nil || turn.ReturnReceipt != nil {
			return errors.New("receipt-era turn commitments are not valid in v4")
		}
		s := turn.Scope
		if s.CeremonyID != c.CeremonyID || (s.Phase != "phase1" && s.Phase != "phase2") || s.Index == 0 || s.Index > 20 || s.ParticipantID == "" || !taggedHash(s.ParentHeadID, "sha256:") {
			return errors.New("invalid turn commitment scope")
		}
		key := fmt.Sprintf("%s/%02d", s.Phase, s.Index)
		if key <= last {
			return errors.New("unordered or duplicate turn commitment")
		}
		last = key
		if turn.Allocations == nil || len(turn.Allocations) == 0 || len(turn.Allocations) > 16 {
			return errors.New("invalid allocation commitment history")
		}
		previousSequence := c.Sequence + 1
		for _, allocation := range turn.Allocations {
			if allocation.CheckpointSequence >= previousSequence || allocation.CheckpointSequence == 0 {
				return errors.New("invalid candidate allocation order")
			}
			previousSequence = allocation.CheckpointSequence
			if err := validatePairV4(allocation.Checkpoint); err != nil {
				return err
			}
			if !commitmentAttemptV4(c, s, allocation.AttemptID, false) {
				return errors.New("candidate allocation has no matching delivery")
			}
			if _, err := time.Parse(time.RFC3339Nano, allocation.AllocatedAt); err != nil {
				return errors.New("candidate allocation has invalid time")
			}
		}
		if r := turn.AcceptedChain; r != nil {
			if err := validatePairV4(r.Pair); err != nil {
				return err
			}
			matched := false
			for _, slot := range c.Deliveries {
				if slot.Scope == s && slot.AttemptID == r.AttemptID && slot.Kind == "candidate" && slot.Status == "accepted" && slot.ContributionResultID == r.ContributionResultID && taggedHash(r.ContributionResultID, "sha256:") {
					matched = true
				}
			}
			if !matched {
				return errors.New("accepted chain has no matching candidate result")
			}
		}
	}
	return nil
}

func commitmentAttemptV4(c CheckpointStateV4, scope ContributionScopeV4, id string, accepted bool) bool {
	for _, slot := range c.Deliveries {
		if slot.Scope == scope && slot.AttemptID == id && slot.Kind == "candidate" && (!accepted || slot.Status == "accepted") {
			return true
		}
	}
	return false
}

type CommittedEnrollmentMetadataV4 struct {
	Refs SignedArtifactRefs `json:"refs"`
	// Only the public fields needed by guidance; parsed from approved-tool
	// output, never directly from a storage enrollment file.
	Enrollment EnrollmentInspection `json:"enrollment"`
}

type EnrollmentMetadataV4 struct {
	CeremonyID  string                          `json:"ceremony_id"`
	Checkpoint  SignedArtifactRefs              `json:"checkpoint"`
	Enrollments []CommittedEnrollmentMetadataV4 `json:"enrollments"`
}

type EnrollmentMetadataInspectionV4 struct {
	Schema                       string               `json:"schema"`
	Depth                        string               `json:"depth"`
	Metadata                     EnrollmentMetadataV4 `json:"metadata"`
	EnrollmentSignaturesVerified bool                 `json:"enrollment_signatures_verified"`
	DisclosureContentsVerified   bool                 `json:"disclosure_contents_verified"`
	CompleteRosterVerified       bool                 `json:"complete_roster_verified"`
	GlobalFreshnessVerified      bool                 `json:"global_freshness_verified"`
}

func (i Inspector) CheckpointEnrollmentsV4(root, record, signature string) (EnrollmentMetadataInspectionV4, error) {
	r, err := i.checkpointV4("inspect-enrollments-v4", root, record, signature)
	if err != nil {
		return EnrollmentMetadataInspectionV4{}, err
	}
	if r.Command != "checkpoint inspect-enrollments-v4" || r.EnrollmentMetadataV4 == nil {
		return EnrollmentMetadataInspectionV4{}, errors.New("missing committed enrollment inspection")
	}
	return validateEnrollmentMetadataV4(*r.EnrollmentMetadataV4)
}

// One approved command verifies ancestry and enrollment signatures together.
// Distinct projections keep structural and record verification claims separate.
func (i Inspector) CheckpointGuidanceV4(root, record, signature string) (CheckpointInspectionV4, EnrollmentMetadataInspectionV4, error) {
	r, err := i.checkpointV4("inspect-enrollments-v4", root, record, signature)
	if err != nil {
		return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, err
	}
	if r.Command != "checkpoint inspect-enrollments-v4" || r.CheckpointInspectionV4 == nil || r.EnrollmentMetadataV4 == nil {
		return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, errors.New("missing combined checkpoint guidance inspection")
	}
	c, err := validateStoredInspectionV4(*r.CheckpointInspectionV4)
	if err != nil {
		return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, err
	}
	e, err := validateEnrollmentMetadataV4(*r.EnrollmentMetadataV4)
	if err != nil {
		return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, err
	}
	if e.Metadata.CeremonyID != c.Checkpoint.CeremonyID || e.Metadata.Checkpoint != c.CheckpointRefs || len(e.Metadata.Enrollments) != len(c.Commitments.Enrollments) {
		return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, errors.New("guidance metadata differs from checkpoint")
	}
	for n, item := range e.Metadata.Enrollments {
		if item.Refs != c.Commitments.Enrollments[n] {
			return CheckpointInspectionV4{}, EnrollmentMetadataInspectionV4{}, errors.New("guidance enrollment set differs from checkpoint")
		}
	}
	return c, e, nil
}

func validateEnrollmentMetadataV4(p EnrollmentMetadataInspectionV4) (EnrollmentMetadataInspectionV4, error) {
	if p.Schema != "proof-tool-mpc-enrollment-metadata-v4" || p.Depth != "committed-enrollment-signatures" || !p.EnrollmentSignaturesVerified || p.DisclosureContentsVerified || p.CompleteRosterVerified || p.GlobalFreshnessVerified || !taggedHash(p.Metadata.CeremonyID, "sha256:") || p.Metadata.Enrollments == nil || len(p.Metadata.Enrollments) > 128 {
		return EnrollmentMetadataInspectionV4{}, errors.New("invalid enrollment metadata verification boundary")
	}
	if err := validatePairV4(p.Metadata.Checkpoint); err != nil {
		return EnrollmentMetadataInspectionV4{}, err
	}
	last := ""
	seen := map[string]bool{}
	for _, item := range p.Metadata.Enrollments {
		if err := validatePairV4(item.Refs); err != nil {
			return EnrollmentMetadataInspectionV4{}, err
		}
		if item.Refs.Record.Name <= last {
			return EnrollmentMetadataInspectionV4{}, errors.New("unordered or duplicate enrollment metadata")
		}
		last = item.Refs.Record.Name
		e := item.Enrollment
		if e.Schema != "proof-tool-mpc-enrollment-record-v1" || e.CeremonyID != p.Metadata.CeremonyID || e.Identity.ID == "" || e.Identity.DisplayName == "" || !protocolID(e.Identity.KeyID) || !taggedHash(e.Identity.PublicKeyFingerprint, "sha256:") || !taggedHash("ed25519:"+e.Identity.Ed25519PublicKeyHex, "ed25519:") || e.RoleIndex < 1 || e.RoleIndex > 20 || e.EnrolledAt == "" {
			return EnrollmentMetadataInspectionV4{}, errors.New("invalid committed enrollment metadata")
		}
		switch e.Role {
		case "coordinator", "release-signer", "auditor", "participant", "public-witness", "mirror-operator":
		default:
			return EnrollmentMetadataInspectionV4{}, errors.New("invalid committed enrollment role")
		}
		for _, key := range []string{"id:" + e.Identity.ID, "key:" + e.Identity.KeyID, "fingerprint:" + e.Identity.PublicKeyFingerprint, fmt.Sprintf("assignment:%s/%d", e.Role, e.RoleIndex)} {
			if seen[key] {
				return EnrollmentMetadataInspectionV4{}, errors.New("duplicate committed enrollment identity or assignment")
			}
			seen[key] = true
		}
		if err := validateBoundedRefV4(e.IndependenceDisclosure, 1<<20); err != nil {
			return EnrollmentMetadataInspectionV4{}, err
		}
	}
	return p, nil
}

// Key IDs are authenticated labels, not necessarily fingerprints. Match the
// proof-tool protocol's ID grammar instead of imposing an ed25519:<digest>
// convention that the signed ceremony format does not require.
func protocolID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' && r != ':' {
			return false
		}
	}
	return true
}
