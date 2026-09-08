package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func storageSettingsFixture() coordinatorStorageSettings {
	return coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", map[string]string{"provider": "aws", "region": "us-east-1", "published-bucket": "public-fixture", "published-base-url": "https://ceremony.example", "inbox-bucket": "private-fixture", "profile": "coordinator", "issuer-profile": "issuer", "grant-role-arn": "arn:aws:iam::123456789012:role/grants", "grant-role-max-ttl": "1h"}}
}

func TestStorageSettingsImportAndSecretRejection(t *testing.T) {
	w := setupFixture(t)
	s := storageSettingsFixture()
	path := filepath.Join(w.d.Work, "admin-settings.json")
	if err := writeJSONNoReplace(path, s, 0600); err != nil {
		t.Fatal(err)
	}
	w.input = bufio.NewReader(strings.NewReader(path + "\n/secure/credentials\nIMPORT\n"))
	w.run = func([]string) error { t.Fatal("import contacted a child/cloud command"); return nil }
	if err := w.importStorageSettings(); err != nil {
		t.Fatal(err)
	}
	if w.d.Storage["provider"] != "aws" || w.d.Credentials != "/secure/credentials" {
		t.Fatal("settings not retained")
	}
	if !strings.Contains(w.output.(*bytes.Buffer).String(), "not ownership or cloud permissions") {
		t.Fatal("import overstated verification")
	}
	for _, field := range []string{"secret-access-key", "token", "private-key", "credentials"} {
		copy := storageSettingsFixture()
		copy.Settings[field] = "must-not-be-exported"
		if err := copy.validate(); err == nil {
			t.Fatal("accepted secret field", field)
		}
	}
	s.Settings["published-base-url"] = "https://user:secret@example.com"
	if err := s.validate(); err == nil {
		t.Fatal("accepted credential-bearing URL")
	}
}

func TestStorageExportHelperNeverOverwrites(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("requires jq")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "settings.json")
	helper, err := filepath.Abs("../../scripts/storage-setup/coordinator-settings.sh")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(storageSettingsFixture())
	run := func() error {
		cmd := exec.Command("bash", "-c", `set -euo pipefail; die(){ exit 1; }; source "$1"; prepare_coordinator_settings_export "$2"; save_coordinator_settings_export "$2"`, "test", helper, target)
		cmd.Stdin = bytes.NewReader(raw)
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	var restored coordinatorStorageSettings
	if err := setupReadJSON(target, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.validate(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target)
	if err := run(); err == nil {
		t.Fatal("overwrote existing settings")
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(before, after) {
		t.Fatal("changed existing settings")
	}
}
