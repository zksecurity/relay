package storagefirst

import (
	"errors"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

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
