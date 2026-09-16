package storagefirst

import (
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestValidateGrantV4BindsAuthenticatedAllocation(t *testing.T) {
	_, protocol, c, commitments, enrollments, view := enrolledTurnV4(t, "phase1")
	attempt := strings.Repeat("ab", 16)
	commitments.Turns = []transcript.TurnCommitmentV4{{Scope: view.Scope, Allocations: []transcript.CandidateAllocationV4{{CheckpointSequence: 1, Checkpoint: allocationPairV4(1), AttemptID: attempt, AllocatedAt: "2026-09-16T00:00:00Z"}}}}
	c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: access.SubmissionKindCandidate, AttemptID: attempt, Status: "allocated"}}
	snapshot := encodeTurnFixtureV4(t, c, commitments, enrollments)
	snapshot.head = transcript.SignedArtifactRefs{Record: transcript.ArtifactRef{Name: "checkpoints/0001.json", Digest: transcript.Digest{SHA256: digestOfTest("1"), Size: 1}}, Signature: transcript.ArtifactRef{Name: "checkpoints/0001.sig", Digest: transcript.Digest{SHA256: digestOfTest("2"), Size: 1}}}
	prefix, err := (DeliveryScope{CeremonyID: protocol.Definition.CeremonyID, AttemptID: attempt, Kind: access.SubmissionKindCandidate}).Prefix()
	if err != nil {
		t.Fatal(err)
	}
	grant := access.StorageFirstGrant{Schema: access.GrantSchemaV2, Provider: "r2", CeremonyID: protocol.Definition.CeremonyID, GrantRequestID: strings.Repeat("e", 32), CheckpointDigest: allocationPairV4(1).Record.Digest.SHA256, SubmissionKind: access.SubmissionKindCandidate, Phase: "phase1", Index: view.Scope.Index, IdentityID: view.Scope.ParticipantID, AttemptID: attempt, Endpoint: "https://account.r2.cloudflarestorage.com", Region: "auto", InboxBucket: "inbox", Prefix: prefix + "/", ManifestKey: prefix + "/manifest.json", IssuedAt: "2026-09-16T00:00:00Z", ExpiresAt: "2026-09-16T01:00:00Z", Credentials: access.SessionCredentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "token"}}
	destination := GrantDestination{Provider: grant.Provider, Endpoint: grant.Endpoint, Region: grant.Region, InboxBucket: grant.InboxBucket}
	now := time.Date(2026, 9, 16, 0, 30, 0, 0, time.UTC)
	if err := ValidateGrantV4At(snapshot, protocol, view.Scope.ParticipantID, grant, destination, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*access.StorageFirstGrant){
		"checkpoint": func(g *access.StorageFirstGrant) { g.CheckpointDigest = digestOfTest("f") },
		"identity":   func(g *access.StorageFirstGrant) { g.IdentityID = "p2" },
		"attempt":    func(g *access.StorageFirstGrant) { g.AttemptID = strings.Repeat("f", 32) },
		"phase":      func(g *access.StorageFirstGrant) { g.Phase = "phase2" },
		"index":      func(g *access.StorageFirstGrant) { g.Index++ },
		"prefix":     func(g *access.StorageFirstGrant) { g.Prefix = "submissions/other/" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := grant
			mutate(&changed)
			if err := ValidateGrantV4At(snapshot, protocol, view.Scope.ParticipantID, changed, destination, now); err == nil {
				t.Fatal("wrong-scope V4 grant accepted")
			}
		})
	}
}

func storageFirstBoundGrant(cp Checkpoint, slot Slot) access.StorageFirstGrant {
	prefix := strings.TrimSuffix(slot.ManifestKey, "manifest.json")
	return access.StorageFirstGrant{
		Schema: access.GrantSchemaV2, Provider: "r2", CeremonyID: digestOfTest("0"), GrantRequestID: strings.Repeat("e", 32),
		CheckpointDigest: cp.Position.Digest, SubmissionKind: slot.Kind, Phase: slot.Phase, Index: uint8(slot.Index), IdentityID: slot.IdentityID,
		AttemptID: slot.AttemptID, Endpoint: "https://account.r2.cloudflarestorage.com", Region: "auto", InboxBucket: "inbox",
		Prefix: prefix, ManifestKey: slot.ManifestKey, IssuedAt: "2026-09-15T01:00:00Z", ExpiresAt: "2026-09-15T02:00:00Z",
		Credentials: access.SessionCredentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "token"},
	}
}

func TestValidateGrantBindsExactAuthenticatedSlot(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	cp.CeremonyID = digestOfTest("0")
	slot := cp.Slots[0]
	grant := storageFirstBoundGrant(cp, slot)
	destination := GrantDestination{Provider: grant.Provider, Endpoint: grant.Endpoint, Region: grant.Region, InboxBucket: grant.InboxBucket}
	now := time.Date(2026, 9, 15, 1, 30, 0, 0, time.UTC)
	if err := ValidateGrantAt(cp, grant, destination, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*access.StorageFirstGrant){
		"checkpoint": func(g *access.StorageFirstGrant) { g.CheckpointDigest = digestOfTest("f") },
		"identity":   func(g *access.StorageFirstGrant) { g.IdentityID = "participant-2" },
		"kind":       func(g *access.StorageFirstGrant) { g.SubmissionKind = "receipt" },
		"attempt":    func(g *access.StorageFirstGrant) { g.AttemptID = strings.Repeat("f", 32) },
		"ceremony":   func(g *access.StorageFirstGrant) { g.CeremonyID = digestOfTest("f") },
		"other safe prefix": func(g *access.StorageFirstGrant) {
			g.Prefix = "submissions/other/"
			g.ManifestKey = g.Prefix + "manifest.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := grant
			mutate(&changed)
			if err := ValidateGrantAt(cp, changed, destination, now); err == nil {
				t.Fatal("wrong-scope grant accepted")
			}
		})
	}
	cp.authenticatedEvidence = false
	if err := ValidateGrantAt(cp, grant, destination, now); err == nil {
		t.Fatal("shallow checkpoint accepted")
	}
	cp.authenticatedEvidence = true
	if err := ValidateGrantAt(cp, grant, destination, time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired exact-slot grant accepted")
	}
	wrongDestination := destination
	wrongDestination.InboxBucket = "another-inbox"
	if err := ValidateGrantAt(cp, grant, wrongDestination, now); err == nil {
		t.Fatal("grant for another storage destination accepted")
	}
}

func TestStorageFirstGrantRejectsExcessiveLifetime(t *testing.T) {
	cp := actionCheckpoint(2, "phase1-receipt-accepted", "participant-1")
	grant := storageFirstBoundGrant(cp, cp.Slots[0])
	grant.ExpiresAt = time.Date(2026, 9, 15, 2, 0, 1, 0, time.UTC).Format(time.RFC3339)
	if err := grant.Validate(); err == nil {
		t.Fatal("overlong temporary credential accepted")
	}
}
