package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
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
