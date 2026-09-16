package storagefirst

import (
	"errors"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

// ValidateGrantV4At binds temporary upload credentials to the exact active
// candidate allocation in a fully authenticated V4 snapshot. The grant's own
// fields are never sufficient authorization.
func ValidateGrantV4At(snapshot SnapshotV4, protocol transcript.DefinitionProtocol, identity string, grant access.StorageFirstGrant, destination GrantDestination, now time.Time) error {
	if err := grant.CheckUnexpired(now); err != nil {
		return err
	}
	if grant.CeremonyID != protocol.Definition.CeremonyID || grant.IdentityID != identity || grant.SubmissionKind != access.SubmissionKindCandidate {
		return errors.New("grant belongs to another ceremony, participant or submission kind")
	}
	if grant.Provider != destination.Provider || grant.Endpoint != destination.Endpoint || grant.Region != destination.Region || grant.InboxBucket != destination.InboxBucket {
		return errors.New("grant storage destination differs from the verified local storage setup")
	}
	view, err := snapshot.TurnV4(protocol, grant.Phase, identity)
	if err != nil {
		return err
	}
	if view.Stage != TurnCandidateV4 || view.CandidateAttempt == nil || view.Scope.Index != grant.Index || view.CandidateAttempt.AttemptID != grant.AttemptID {
		return errors.New("grant does not match the active authenticated candidate allocation")
	}
	var allocation *transcript.CandidateAllocationV4
	if view.Commitment != nil {
		for n := range view.Commitment.Allocations {
			if view.Commitment.Allocations[n].AttemptID == grant.AttemptID {
				allocation = &view.Commitment.Allocations[n]
				break
			}
		}
	}
	if allocation == nil || grant.CheckpointDigest != allocation.Checkpoint.Record.Digest.SHA256 {
		return errors.New("grant checkpoint differs from the authenticated allocation checkpoint")
	}
	prefix, err := (DeliveryScope{CeremonyID: grant.CeremonyID, AttemptID: grant.AttemptID, Kind: access.SubmissionKindCandidate}).Prefix()
	if err != nil {
		return err
	}
	if grant.Prefix != prefix+"/" || grant.ManifestKey != prefix+"/manifest.json" {
		return errors.New("grant object scope differs from the authenticated candidate attempt")
	}
	return nil
}

type GrantDestination struct {
	Provider    string
	Endpoint    string
	Region      string
	InboxBucket string
}

// ValidateGrant binds a decoded temporary credential to one exact allocated
// slot in a fully evidence-verified checkpoint. Self-consistent grant JSON is
// never enough to authorize an upload.
func ValidateGrantAt(checkpoint Checkpoint, grant access.StorageFirstGrant, destination GrantDestination, now time.Time) error {
	if !checkpoint.authenticatedEvidence {
		return errors.New("grant validation requires a fully evidence-verified checkpoint")
	}
	if err := grant.CheckUnexpired(now); err != nil {
		return err
	}
	if grant.CeremonyID != checkpoint.CeremonyID {
		return errors.New("grant belongs to another ceremony")
	}
	if grant.Provider != destination.Provider || grant.Endpoint != destination.Endpoint || grant.Region != destination.Region || grant.InboxBucket != destination.InboxBucket {
		return errors.New("grant storage destination differs from the verified local storage setup")
	}
	var slot *Slot
	for i := range checkpoint.Slots {
		candidate := &checkpoint.Slots[i]
		if candidate.Kind == grant.SubmissionKind && candidate.Phase == grant.Phase && candidate.Index == int(grant.Index) &&
			candidate.IdentityID == grant.IdentityID && candidate.AttemptID == grant.AttemptID {
			slot = candidate
			break
		}
	}
	if slot == nil || slot.Status != "allocated" {
		return errors.New("grant does not match an allocated submission slot")
	}
	if grant.CheckpointDigest != checkpoint.Position.Digest || grant.ManifestKey != slot.ManifestKey ||
		grant.Prefix != strings.TrimSuffix(slot.ManifestKey, "manifest.json") {
		return errors.New("grant checkpoint or object scope differs from the authenticated submission slot")
	}
	return nil
}
