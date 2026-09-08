package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r2WizardFixture(t *testing.T, mode string) *coordinatorWizard {
	t.Helper()
	w := setupFixture(t)
	w.credentialRoot = filepath.Join(t.TempDir(), "credentials")
	input := "2\n" + strings.Repeat("a", 32) + "\npublished-bucket\ninbox-bucket\nhttps://public.example.test\n" + mode + "\n2\n1\n1\n1\n1\n1\nSAVE SETTINGS\n"
	w.input = bufio.NewReader(strings.NewReader(input))
	values := []string{strings.Repeat("b", 32), strings.Repeat("c", 64), strings.Repeat("d", 32), strings.Repeat("e", 64), "test-only-control-token"}
	w.readSecret = func(string) (string, error) {
		if len(values) == 0 {
			t.Fatal("unexpected credential request")
		}
		v := values[0]
		values = values[1:]
		return v, nil
	}
	return &w
}

func TestR2SetupStagesPrivateDedicatedCredentials(t *testing.T) {
	w := r2WizardFixture(t, "1")
	if err := w.setupR2(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{w.d.Credentials, w.d.R2Parent, w.d.R2Control} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe credential file", err)
		}
		if strings.HasPrefix(path, w.d.Work+"/") || strings.HasPrefix(path, w.d.Keys+"/") {
			t.Fatal("credential staged into public work or signing keys")
		}
	}
	raw, err := os.ReadFile(w.draftPath)
	if err != nil {
		t.Fatal(err)
	}
	output := w.output.(*bytes.Buffer).String() + string(raw)
	for _, secret := range []string{strings.Repeat("c", 64), strings.Repeat("e", 64), "test-only-control-token"} {
		if strings.Contains(output, secret) {
			t.Fatal("secret leaked into public prompts or draft")
		}
	}
	if w.d.Storage["endpoint"] != "https://"+strings.Repeat("a", 32)+".r2.cloudflarestorage.com" {
		t.Fatal("endpoint not derived")
	}
	if err := w.cleanupSessionCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.d.R2Parent); err != nil {
		t.Fatal("persistent credentials removed")
	}
}

func TestR2SessionCleanupAndCancelledReplacement(t *testing.T) {
	w := r2WizardFixture(t, "2")
	if err := w.setupR2(); err != nil {
		t.Fatal(err)
	}
	old := w.d.R2Parent
	if err := w.cleanupSessionCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("session credential survived cleanup")
	}
	w = r2WizardFixture(t, "1")
	w.readSecret = func(string) (string, error) { return "", errSecretPromptInterrupted }
	w.d.R2Parent = "/retained/old-credential"
	if err := w.setupR2(); !errors.Is(err, errSecretPromptInterrupted) {
		t.Fatal(err)
	}
	if w.d.R2Parent != "/retained/old-credential" {
		t.Fatal("cancelled replacement changed old references")
	}
	if _, err := os.Stat(w.credentialRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled entry wrote credentials")
	}
}

func TestStorageInfrastructureDoesNotInventCeremony(t *testing.T) {
	s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", map[string]string{"provider": "r2", "region": "auto", "profile": "coordinator", "account-id": strings.Repeat("a", 32), "endpoint": "https://" + strings.Repeat("a", 32) + ".r2.cloudflarestorage.com", "parent-access-key-id": strings.Repeat("b", 32), "published-bucket": "published", "inbox-bucket": "inbox", "published-base-url": "https://public.example.test"}}
	c, err := s.infrastructure()
	if err != nil {
		t.Fatal(err)
	}
	if c.CeremonyID != "" || c.CeremonyPath != "" || c.Schema != "" {
		t.Fatal("fabricated ceremony binding")
	}
	if err := c.Validate(); err == nil {
		t.Fatal("preinitialization settings accepted as ceremony configuration")
	}
}
