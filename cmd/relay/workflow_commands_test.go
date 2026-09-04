package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
)

func TestCollectEvidenceRejectsSymlinksAndSecrets(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "audit.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.sig")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := collectEvidence(nil, dir); err == nil {
		t.Fatal("evidence symlink accepted")
	}
	if _, err := collectEvidence([]string{"release-signing-key.hex"}, ""); err == nil {
		t.Fatal("possible signing key accepted")
	}
}

func TestParticipateV2ProfileRequiresTurnGrant(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "participant.json")
	config := access.ParticipantConfig{
		Schema: access.ParticipantConfigSchema, Phase: "phase1", Root: filepath.Join(dir, "ceremony"),
		Ceremony: filepath.Join(dir, "ceremony.json"), CeremonySignature: filepath.Join(dir, "ceremony.sig"),
		CoordinatorKey: filepath.Join(dir, "coordinator.hex"), CeremonyBinary: "mpc-ceremony",
		SigningKey: filepath.Join(dir, "participant.hex"), Environment: filepath.Join(dir, "environment.json"),
		CandidateParentDir: filepath.Join(dir, "candidates"), PublishedBaseURL: "https://ceremony.example",
		PublishedBucket: "published",
	}
	if err := writeJSONNoReplace(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runParticipate([]string{"--config", configPath})
	if err == nil || !strings.Contains(err.Error(), "temporary upload grant") {
		t.Fatalf("missing grant error = %v", err)
	}
}

func TestManifestKeysOnlyReturnsSafeCompletedSubmissions(t *testing.T) {
	objects := []store.Object{
		{Key: "candidates/id/person/phase1/0001/attempt/contribution.bin"},
		{Key: "candidates/id/person/phase1/0001/attempt/manifest.json"},
		{Key: "../manifest.json"},
	}
	got := manifestKeys(objects)
	if len(got) != 1 || got[0] != objects[1].Key {
		t.Fatalf("manifest keys = %q", got)
	}
}

type candidateStoreFake struct {
	objects map[string][]byte
	puts    []string
	failKey string
}

func (f *candidateStoreFake) PutNoReplace(key, localPath string) error {
	if key == f.failKey {
		return errors.New("temporary upload failure")
	}
	if _, exists := f.objects[key]; exists {
		return store.ErrExists
	}
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	f.objects[key] = append([]byte(nil), raw...)
	f.puts = append(f.puts, key)
	return nil
}

func (f *candidateStoreFake) Get(key, localPath string) error {
	raw, exists := f.objects[key]
	if !exists {
		return os.ErrNotExist
	}
	return os.WriteFile(localPath, raw, 0o600)
}

func candidateFixture(t *testing.T) (string, string, access.CandidateManifest) {
	t.Helper()
	dir := t.TempDir()
	manifest := access.CandidateManifest{
		Schema: access.CandidateManifestSchema, CeremonyID: "sha256:" + strings.Repeat("a", 64),
		Phase: "phase1", Index: 3, ParticipantID: "participant-03",
		ParentChainSHA256: "sha256:" + strings.Repeat("b", 64),
		AttemptID:         strings.Repeat("c", 32), CompletedAt: "2026-08-29T12:00:00Z",
	}
	for _, name := range candidateFileNames {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("contents of "+name), 0o600); err != nil {
			t.Fatal(err)
		}
		ref, err := regularFileRef(filepath.Join(dir, name), name)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, ref)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, localCandidateManifestName)
	if err := writeJSONNoReplace(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, manifestPath, manifest
}

func TestUploadCandidateResumesMatchingPartialUpload(t *testing.T) {
	dir, manifestPath, manifest := candidateFixture(t)
	grantPrefix, err := access.Prefix(manifest.CeremonyID, access.RoleParticipant, manifest.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := grantPrefix + "phase1/0003/" + manifest.AttemptID + "/"
	fake := &candidateStoreFake{objects: make(map[string][]byte), failKey: prefix + "attestation.sig"}

	if _, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest); err == nil {
		t.Fatal("interrupted upload succeeded")
	}
	if len(fake.objects) != 2 {
		t.Fatalf("partial object count = %d, want 2", len(fake.objects))
	}

	fake.failKey = ""
	manifestKey, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if manifestKey != prefix+"manifest.json" {
		t.Fatalf("manifest key = %q", manifestKey)
	}
	if len(fake.objects) != len(candidateFileNames)+1 {
		t.Fatalf("completed object count = %d", len(fake.objects))
	}
	if got := fake.puts[len(fake.puts)-1]; got != manifestKey {
		t.Fatalf("last created object = %q, want manifest %q", got, manifestKey)
	}
	created := len(fake.puts)
	if got, err := uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest); err != nil || got != manifestKey {
		t.Fatalf("completed retry = %q, %v", got, err)
	}
	if len(fake.puts) != created {
		t.Fatalf("completed retry created %d extra objects", len(fake.puts)-created)
	}
}

func TestUploadCandidateRejectsConflictingExistingObject(t *testing.T) {
	dir, manifestPath, manifest := candidateFixture(t)
	grantPrefix, err := access.Prefix(manifest.CeremonyID, access.RoleParticipant, manifest.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := grantPrefix + "phase1/0003/" + manifest.AttemptID + "/"
	fake := &candidateStoreFake{objects: map[string][]byte{
		prefix + candidateFileNames[0]: []byte("different bytes"),
	}}

	_, err = uploadCandidate(fake, grantPrefix, dir, manifestPath, manifest)
	if err == nil || !strings.Contains(err.Error(), "conflicts with the saved candidate") {
		t.Fatalf("conflicting upload error = %v", err)
	}
}

func TestVerifyLocalCandidateRejectsChangedFile(t *testing.T) {
	dir, _, manifest := candidateFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "erasure.json"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalCandidate(dir, manifest); err == nil || !strings.Contains(err.Error(), "recorded digest") {
		t.Fatalf("changed candidate error = %v", err)
	}
}

func TestCandidateDestroyedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "erasure.json")
	if err := os.WriteFile(path, []byte(`{"destroyed_at":"2026-09-04T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := candidateDestroyedAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-09-04T12:00:00Z" {
		t.Fatalf("destroyed_at = %q", got)
	}

	if err := os.WriteFile(path, []byte(`{"destroyed_at":"not-a-time"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateDestroyedAt(dir); err == nil {
		t.Fatal("invalid destroyed_at accepted")
	}
}

func TestValidateResumableCandidateRejectsAdvancedHead(t *testing.T) {
	_, _, manifest := candidateFixture(t)
	config := access.ParticipantConfig{Phase: manifest.Phase}
	grant := access.Grant{
		CeremonyID: manifest.CeremonyID, IdentityID: manifest.ParticipantID,
	}
	pos := position{
		nextID: manifest.ParticipantID, nextIndex: manifest.Index + 1,
		pointer: state.Pointer{Chain: state.Ref{SHA256: "sha256:" + strings.Repeat("d", 64)}},
	}
	if err := validateResumableCandidate(manifest, config, grant, pos); err == nil || !strings.Contains(err.Error(), "different ceremony head") {
		t.Fatalf("advanced-head error = %v", err)
	}
}
