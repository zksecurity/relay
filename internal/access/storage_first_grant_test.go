package access

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validStorageFirstGrant() StorageFirstGrant {
	attempt := strings.Repeat("b", 32)
	prefix := "submissions/phase1/0001/receipt/participant-03/" + attempt + "/"
	return StorageFirstGrant{
		Schema: GrantSchemaV2, Provider: "r2", CeremonyID: testCeremony,
		GrantRequestID: strings.Repeat("a", 32), CheckpointDigest: "sha256:" + strings.Repeat("c", 64),
		SubmissionKind: SubmissionKindReceipt, Phase: "phase1", Index: 1,
		IdentityID: "participant-03", AttemptID: attempt,
		Endpoint: "https://account.r2.cloudflarestorage.com", Region: "auto", InboxBucket: "inbox",
		Prefix: prefix, ManifestKey: prefix + "manifest.json",
		IssuedAt: "2026-09-15T01:00:00Z", ExpiresAt: "2026-09-15T02:00:00Z",
		Credentials: SessionCredentials{AccessKeyID: "temporary-id", SecretAccessKey: "temporary-secret", SessionToken: "temporary-token"},
	}
}

func TestStorageFirstGrantStrictBinding(t *testing.T) {
	valid := validStorageFirstGrant()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid grant: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*StorageFirstGrant)
	}{
		{"request", func(g *StorageFirstGrant) { g.GrantRequestID = "request" }},
		{"checkpoint", func(g *StorageFirstGrant) { g.CheckpointDigest = strings.Repeat("c", 64) }},
		{"kind", func(g *StorageFirstGrant) { g.SubmissionKind = "release" }},
		{"phase", func(g *StorageFirstGrant) { g.Phase = "phase2" }},
		{"index", func(g *StorageFirstGrant) { g.Index = 0 }},
		{"identity", func(g *StorageFirstGrant) { g.IdentityID = "../other" }},
		{"attempt", func(g *StorageFirstGrant) { g.AttemptID = strings.Repeat("A", 32) }},
		{"prefix traversal", func(g *StorageFirstGrant) { g.Prefix = "submissions/../other/" }},
		{"manifest outside prefix", func(g *StorageFirstGrant) { g.ManifestKey = "other/manifest.json" }},
		{"noncanonical time", func(g *StorageFirstGrant) { g.IssuedAt = "2026-09-15T10:00:00+09:00" }},
		{"expiry", func(g *StorageFirstGrant) { g.ExpiresAt = g.IssuedAt }},
		{"credentials", func(g *StorageFirstGrant) { g.Credentials.SessionToken = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := valid
			test.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("changed grant accepted")
			}
		})
	}
}

func TestStorageFirstGrantRenewalPreservesAttemptAndScope(t *testing.T) {
	previous := validStorageFirstGrant()
	renewed := previous
	renewed.GrantRequestID = strings.Repeat("d", 32)
	renewed.IssuedAt = "2026-09-15T01:30:00Z"
	renewed.ExpiresAt = "2026-09-15T02:30:00Z"
	renewed.Credentials = SessionCredentials{AccessKeyID: "renewed-id", SecretAccessKey: "renewed-secret", SessionToken: "renewed-token"}
	if err := renewed.ValidateRenewal(previous); err != nil {
		t.Fatalf("same-attempt renewal: %v", err)
	}

	for _, mutate := range []func(*StorageFirstGrant){
		func(g *StorageFirstGrant) { g.AttemptID = strings.Repeat("e", 32) },
		func(g *StorageFirstGrant) {
			g.Prefix = "submissions/other/"
			g.ManifestKey = g.Prefix + "manifest.json"
		},
		func(g *StorageFirstGrant) { g.CheckpointDigest = "sha256:" + strings.Repeat("f", 64) },
		func(g *StorageFirstGrant) { g.IdentityID = "participant-04" },
		func(g *StorageFirstGrant) { g.GrantRequestID = previous.GrantRequestID },
		func(g *StorageFirstGrant) { g.ExpiresAt = previous.ExpiresAt },
	} {
		changed := renewed
		mutate(&changed)
		if err := changed.ValidateRenewal(previous); err == nil {
			t.Fatal("scope-changing or non-extending renewal accepted")
		}
	}
}

func TestStorageFirstGrantStrictDecodeAndExpiry(t *testing.T) {
	grant := validStorageFirstGrant()
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, StorageFirstGrant.Validate)
	if err != nil || decoded.AttemptID != grant.AttemptID {
		t.Fatalf("decode: %#v, %v", decoded, err)
	}
	withUnknown := append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
	if _, err := Decode(withUnknown, StorageFirstGrant.Validate); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := grant.CheckUnexpired(time.Date(2026, 9, 15, 1, 59, 59, 0, time.UTC)); err != nil {
		t.Fatalf("unexpired grant rejected: %v", err)
	}
	if err := grant.CheckUnexpired(time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired grant accepted")
	}
	future := grant
	future.IssuedAt = "2036-09-15T01:00:00Z"
	future.ExpiresAt = "2036-09-15T02:00:00Z"
	if err := future.CheckUnexpired(time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("far-future grant accepted as a long-lived credential")
	}
	skew := grant
	skew.IssuedAt = "2026-09-15T01:05:00Z"
	skew.ExpiresAt = "2026-09-15T02:05:00Z"
	if err := skew.CheckUnexpired(time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("boundary clock skew rejected: %v", err)
	}
}
