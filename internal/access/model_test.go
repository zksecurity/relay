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

func TestParticipantConfigV2DefersTemporaryGrant(t *testing.T) {
	config := ParticipantConfig{
		Schema: ParticipantConfigSchema, Phase: "phase1", Root: "/ceremony",
		Ceremony: "/ceremony/ceremony.json", CeremonySignature: "/ceremony/ceremony.sig",
		CoordinatorKey: "/trusted/coordinator.hex", CeremonyBinary: "/usr/local/bin/mpc-ceremony",
		SigningKey: "/keys/participant.hex", Environment: "/config/environment.json",
		CandidateParentDir: "/work/candidates", PublishedBaseURL: "https://ceremony.example",
		PublishedBucket: "published",
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("v2 profile without temporary grant: %v", err)
	}
	config.Schema = ParticipantConfigSchemaV1
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "grant_path") {
		t.Fatalf("v1 profile without grant error = %v", err)
	}
}

func TestParticipantConfigRequiresImmutableDockerImage(t *testing.T) {
	config := ParticipantConfig{
		Schema: ParticipantConfigSchema, Phase: "phase1", Root: "/ceremony",
		Ceremony: "/ceremony/ceremony.json", CeremonySignature: "/ceremony/ceremony.sig",
		CoordinatorKey: "/trusted/coordinator.hex", CeremonyBinary: "/usr/local/bin/mpc-ceremony",
		SigningKey: "/keys/participant.hex", Environment: "/config/environment.json",
		CandidateParentDir: "/work/candidates", PublishedBaseURL: "https://ceremony.example",
		PublishedBucket: "published", ExecutionMode: "docker", DockerPlatform: "linux/arm64",
		DockerCLI: "docker", DockerImage: "ceremony-tool:latest",
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "immutable sha256") {
		t.Fatalf("mutable image error = %v", err)
	}
	config.DockerImage = "sha256:" + strings.Repeat("a", 64)
	if err := config.Validate(); err != nil {
		t.Fatalf("immutable local image ID: %v", err)
	}
	config.Schema = ParticipantConfigSchemaV2
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "latest configuration schema") {
		t.Fatalf("legacy Docker profile error = %v", err)
	}
	config.Schema = ParticipantConfigSchema
	config.DockerImage = "registry.example/ceremony-tool@sha256:" + strings.Repeat("b", 64)
	if err := config.Validate(); err != nil {
		t.Fatalf("immutable repository digest: %v", err)
	}
	config.DockerPlatform = "linux/s390x"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "linux/amd64 or linux/arm64") {
		t.Fatalf("unsupported platform error = %v", err)
	}
}

func TestRoleConfigSeparatesPersistentPathsFromTemporaryAccess(t *testing.T) {
	participant := RoleConfig{
		Schema: RoleConfigSchema, Role: RoleParticipant, IdentityID: "participant-01",
		Phase: "phase1", CeremonyID: testCeremony, CeremonyHome: "/ceremonies/example",
		Root: "/ceremonies/example/public", Ceremony: "/ceremonies/example/public/ceremony.json",
		CeremonySignature: "/ceremonies/example/public/ceremony.sig",
		CoordinatorKey:    "/trusted/coordinator.hex", CeremonyBinary: "/usr/local/bin/mpc-ceremony",
		SigningKey: "/secure/participant-01.hex", Environment: "/secure/environment.json",
		RunRoot: "/ceremonies/example/run", StorageConfig: "/ceremonies/example/config/relay-storage.json",
		PublishedBaseURL: "https://ceremony.example", PublishedBucket: "published",
	}
	if err := participant.Validate(); err != nil {
		t.Fatal(err)
	}
	witness := participant
	witness.Role = RoleWitness
	witness.IdentityID = "witness-01"
	witness.SigningKey = ""
	witness.Environment = ""
	witness.Enrollment = "/trusted/witness-01.json"
	witness.EnrollmentSignature = "/trusted/witness-01.sig"
	if err := witness.Validate(); err != nil {
		t.Fatal(err)
	}
	witness.SigningKey = "/secure/witness-01.hex"
	if err := witness.Validate(); err == nil || !strings.Contains(err.Error(), "must not retain") {
		t.Fatalf("non-participant retained signing key error = %v", err)
	}
}
