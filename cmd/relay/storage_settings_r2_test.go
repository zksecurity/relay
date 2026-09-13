package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r2ImportFixture(t *testing.T) (*coordinatorWizard, []string) {
	t.Helper()
	source := r2WizardFixture(t, "1")
	if err := source.setupR2(); err != nil {
		t.Fatal(err)
	}
	w := setupFixture(t)
	w.credentialRoot = filepath.Join(t.TempDir(), "copies")
	w.run = func([]string) error { t.Fatal("import contacted a child or cloud command"); return nil }
	s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", source.d.Storage}
	s.Settings["profile"] = "old-profile"
	// Another supported profile must not leak into the new dedicated file.
	raw := "[old-profile]\naws_access_key_id = " + strings.Repeat("b", 32) + "\naws_secret_access_key = " + strings.Repeat("c", 64) + "\n[unselected]\naws_access_key_id = " + strings.Repeat("1", 32) + "\naws_secret_access_key = " + strings.Repeat("2", 64) + "\n"
	if err := os.WriteFile(source.d.Credentials, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.d.Work, "storage-settings.json")
	if err := writeJSONNoReplace(path, s, 0600); err != nil {
		t.Fatal(err)
	}
	return &w, []string{path, source.d.Credentials, source.d.R2Parent, source.d.R2Control}
}

func TestImportR2SettingsCompletesCredentialSetup(t *testing.T) {
	for _, mode := range []string{"1", "2"} {
		t.Run(mode, func(t *testing.T) {
			w, paths := r2ImportFixture(t)
			originals := map[string][]byte{}
			for _, path := range paths {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				originals[path] = raw
			}
			w.input = bufio.NewReader(strings.NewReader(strings.Join(paths, "\n") + "\n" + mode + "\nIMPORT\n"))
			if err := w.importStorageSettings(); err != nil {
				t.Fatal(err)
			}
			if next := w.nextPreparationAction(); next.choice != "8" {
				t.Fatal("storage loop remains", next)
			}
			if w.d.Storage["profile"] != "relay-coordinator" {
				t.Fatal("staged profile mismatch")
			}
			raw, err := os.ReadFile(w.d.Credentials)
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := parseR2CoordinatorProfiles(raw)
			if err != nil || len(profiles) != 1 || profiles["relay-coordinator"][0] != strings.Repeat("b", 32) {
				t.Fatal("wrong profile copied")
			}
			for _, path := range []string{w.d.Credentials, w.d.R2Parent, w.d.R2Control} {
				if _, ok := originals[path]; ok {
					t.Fatal("adopted source as owned copy")
				}
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("unprotected copy")
				}
			}
			out := w.output.(*bytes.Buffer).String()
			for _, secret := range []string{strings.Repeat("c", 64), strings.Repeat("e", 64), "test-only-control-token"} {
				if strings.Contains(out, secret) {
					t.Fatal("secret printed")
				}
			}
			if !strings.Contains(out, "cloud access has not been checked") {
				t.Fatal("misleading success")
			}
			if err := w.cleanupSessionCredentials(); err != nil {
				t.Fatal(err)
			}
			for path, before := range originals {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("source changed during import or cleanup")
				}
			}
		})
	}
}

func TestImportR2CancelAndSaveFailurePreserveOldSetup(t *testing.T) {
	for stop := 0; stop < 8; stop++ {
		t.Run(string(rune('a'+stop)), func(t *testing.T) {
			w, paths := r2ImportFixture(t)
			w.d.Credentials = "/previous/aws"
			w.d.R2Parent = "/previous/parent"
			w.d.R2Control = "/previous/control"
			before, _ := json.Marshal(w.d)
			answers := append(append([]string{}, paths...), "1", "IMPORT")
			switch {
			case stop < 6:
				answers = answers[:stop]
			case stop == 6:
				answers[5] = "NO"
			case stop == 7:
				w.draftPath = filepath.Join(w.d.Work, "absent-parent", "draft.json")
			}
			text := strings.Join(answers, "\n")
			if len(answers) > 0 {
				text += "\n"
			}
			w.input = bufio.NewReader(strings.NewReader(text))
			if err := w.importStorageSettings(); err == nil {
				t.Fatal("unexpected successful incomplete import")
			}
			after, _ := json.Marshal(w.d)
			if !bytes.Equal(before, after) {
				t.Fatal("previous draft changed")
			}
			entries, err := os.ReadDir(w.credentialRoot)
			if err == nil && len(entries) != 0 {
				t.Fatal("uncommitted credential copies retained")
			}
			for _, path := range paths {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("source removed")
				}
			}
		})
	}
}

func TestImportR2RejectsInvalidCredentialFiles(t *testing.T) {
	for _, kind := range []string{"same-key", "bad-parent", "missing-control", "public-file", "missing-profile"} {
		t.Run(kind, func(t *testing.T) {
			w, paths := r2ImportFixture(t)
			switch kind {
			case "same-key":
				var s coordinatorStorageSettings
				if err := setupReadJSON(paths[0], &s); err != nil {
					t.Fatal(err)
				}
				s.Settings["parent-access-key-id"] = strings.Repeat("b", 32)
				raw, _ := json.Marshal(s)
				if err := os.WriteFile(paths[0], raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-parent":
				if err := os.WriteFile(paths[2], []byte("not a secret key"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-control":
				if err := os.Remove(paths[3]); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(paths[1], 0644); err != nil {
					t.Fatal(err)
				}
			case "missing-profile":
				if err := os.WriteFile(paths[1], []byte("[other]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w.input = bufio.NewReader(strings.NewReader(strings.Join(paths, "\n") + "\n1\nIMPORT\n"))
			if err := w.importStorageSettings(); err == nil {
				t.Fatal("accepted invalid input")
			}
			if _, err := os.Stat(w.credentialRoot); !os.IsNotExist(err) {
				t.Fatal("created credential copies before validation")
			}
		})
	}
}

func TestStorageProviderSwitchClearsR2OnlyOnCommit(t *testing.T) {
	for _, confirm := range []string{"NO", "IMPORT"} {
		t.Run(confirm, func(t *testing.T) {
			w := setupFixture(t)
			w.d.R2Parent = "/previous/parent"
			w.d.R2Control = "/previous/control"
			path := filepath.Join(w.d.Work, "aws-settings.json")
			if err := writeJSONNoReplace(path, storageSettingsFixture(), 0600); err != nil {
				t.Fatal(err)
			}
			w.input = bufio.NewReader(strings.NewReader(path + "\n/secure/credentials\n" + confirm + "\n"))
			err := w.importStorageSettings()
			if confirm == "NO" {
				if err == nil || w.d.R2Parent != "/previous/parent" || w.d.R2Control != "/previous/control" {
					t.Fatal("cancel changed references")
				}
			} else if err != nil || w.d.R2Parent != "" || w.d.R2Control != "" {
				t.Fatal("committed provider switch retained R2 references", err)
			}
		})
	}
}
