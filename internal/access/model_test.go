package access

import (
	"strings"
	"testing"
	"time"
)

const testCeremony = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGrantPrefixIsIdentityScoped(t *testing.T) {
	want := "candidates/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/participant-03/"
	got, err := Prefix(testCeremony, RoleParticipant, "participant-03")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("prefix = %q, want %q", got, want)
	}
	if _, err := Prefix(testCeremony, RoleParticipant, "../other"); err == nil {
		t.Fatal("path-traversing identity accepted")
	}
}

func TestGrantUsabilityChecksMinimumWindow(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	prefix, _ := Prefix(testCeremony, RoleParticipant, "participant-03")
	grant := Grant{
		Schema: GrantSchema, Provider: "r2", CeremonyID: testCeremony,
		Role: RoleParticipant, IdentityID: "participant-03", InboxBucket: "inbox", Prefix: prefix,
		Endpoint: "https://account.r2.cloudflarestorage.com", Region: "auto",
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(90 * time.Minute).Format(time.RFC3339),
		MinimumRemaining: "2h", Credentials: SessionCredentials{AccessKeyID: "a", SecretAccessKey: "s", SessionToken: "t"},
	}
	if err := grant.CheckUsable(now); err == nil || !strings.Contains(err.Error(), "at least 2h") {
		t.Fatalf("near-expiry grant error = %v", err)
	}
	grant.ExpiresAt = now.Add(3 * time.Hour).Format(time.RFC3339)
	if err := grant.CheckUsable(now); err != nil {
		t.Fatal(err)
	}
	if err := grant.CheckUnexpired(now.Add(2*time.Hour + 59*time.Minute)); err != nil {
		t.Fatalf("post-work unexpired check rejected usable final minute: %v", err)
	}
	if err := grant.CheckUnexpired(now.Add(3 * time.Hour)); err == nil {
		t.Fatal("expired grant accepted")
	}
}

func TestCandidateManifestRequiresExactFiles(t *testing.T) {
	files := []FileRef{}
	for _, name := range []string{"contribution.bin", "attestation.json", "attestation.sig", "erasure.json", "erasure.sig"} {
		files = append(files, FileRef{Name: name, SHA256: testCeremony, Size: 1})
	}
	m := CandidateManifest{Schema: CandidateManifestSchema, CeremonyID: testCeremony, Phase: "phase1", Index: 1,
		ParticipantID: "participant-01", ParentChainSHA256: testCeremony,
		AttemptID: strings.Repeat("b", 32), Files: files, CompletedAt: "2026-08-18T12:00:00Z"}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Files[0].Name = "private-key.hex"
	if err := m.Validate(); err == nil {
		t.Fatal("unexpected candidate file accepted")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"schema":"relay-participant-config-v1","unknown":true}`)
	if _, err := Decode(raw, ParticipantConfig.Validate); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestDecodeRejectsDuplicateFields(t *testing.T) {
	raw := []byte(`{"schema":"relay-participant-config-v1","phase":"phase1","phase":"phase2"}`)
	if _, err := Decode(raw, ParticipantConfig.Validate); err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("duplicate field error = %v", err)
	}
}
