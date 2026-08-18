package main

import (
	"os"
	"path/filepath"
	"testing"

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
