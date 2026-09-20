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

func r2TestProfile(name, id, secret string) string {
	return "[" + name + "]\naws_access_key_id = " + id + "\naws_secret_access_key = " + secret + "\n"
}

func r2ProfileWizardFixture(t *testing.T, sameFile bool) (*coordinatorWizard, []string, []string) {
	t.Helper()
	w := setupFixture(t)
	w.credentialRoot = filepath.Join(t.TempDir(), "copies")
	w.run = func([]string) error { t.Fatal("credential selection started a child command"); return nil }
	w.readSecret = func(label string) (string, error) {
		if label != "R2 control-plane token for checking inbox privacy" {
			t.Fatal("profile selection unexpectedly requested a credential value")
		}
		return "test-only-control-token", nil
	}
	dir := t.TempDir()
	coordinator := filepath.Join(dir, "coordinator")
	inbox := filepath.Join(dir, "inbox")
	coordinatorRaw := r2TestProfile("coordinator", strings.Repeat("b", 32), strings.Repeat("c", 64))
	inboxRaw := r2TestProfile("inbox", strings.Repeat("d", 32), strings.Repeat("e", 64))
	selection := "1"
	if sameFile {
		inbox = coordinator
		coordinatorRaw += inboxRaw + r2TestProfile("unselected", strings.Repeat("1", 32), strings.Repeat("2", 64))
		selection = "2"
	} else if err := os.WriteFile(inbox, []byte(inboxRaw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coordinator, []byte(coordinatorRaw), 0600); err != nil {
		t.Fatal(err)
	}
	answers := []string{"2", strings.Repeat("a", 32), "published-bucket", "inbox-bucket", "https://public.example.test", "1", "1", coordinator, "1", "1", inbox, selection, "1", "SAVE SETTINGS"}
	return &w, []string{coordinator, inbox}, answers
}

func setR2Answers(w *coordinatorWizard, answers []string) {
	text := strings.Join(answers, "\n")
	if len(answers) > 0 {
		text += "\n"
	}
	w.input = bufio.NewReader(strings.NewReader(text))
}

func TestR2SetupSelectsInboxProfile(t *testing.T) {
	for _, sameFile := range []bool{true, false} {
		for _, mode := range []string{"1", "2"} {
			name := "separate-files-" + mode
			if sameFile {
				name = "same-file-" + mode
			}
			t.Run(name, func(t *testing.T) {
				w, paths, answers := r2ProfileWizardFixture(t, sameFile)
				originals := map[string][]byte{}
				for _, path := range paths {
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					originals[path] = raw
				}
				answers[5] = mode
				setR2Answers(w, answers)
				if err := w.setupR2(); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(w.d.Credentials)
				if err != nil {
					t.Fatal(err)
				}
				profiles, err := parseR2CoordinatorProfiles(raw)
				want := [2]string{strings.Repeat("b", 32), strings.Repeat("c", 64)}
				if err != nil || len(profiles) != 1 || profiles["relay-coordinator"] != want {
					t.Fatal("dedicated file did not isolate the coordinator profile")
				}
				parent, err := readProtectedCredential(w.d.R2Parent)
				if err != nil || parent != strings.Repeat("e", 64) || w.d.Storage["parent-access-key-id"] != strings.Repeat("d", 32) {
					t.Fatal("wrong inbox credential saved")
				}
				for _, path := range []string{w.d.Credentials, w.d.R2Parent, w.d.R2Control} {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatal("credential copy is not protected")
					}
				}
				output := w.output.(*bytes.Buffer).String()
				draft, err := os.ReadFile(w.draftPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range []string{strings.Repeat("b", 32), strings.Repeat("d", 32), strings.Repeat("c", 64), strings.Repeat("e", 64), strings.Repeat("2", 64), "test-only-control-token"} {
					if strings.Contains(output, value) {
						t.Fatal("credential value printed")
					}
				}
				for _, secret := range []string{strings.Repeat("c", 64), strings.Repeat("e", 64), strings.Repeat("2", 64), "test-only-control-token"} {
					if bytes.Contains(draft, []byte(secret)) {
						t.Fatal("credential secret stored in draft")
					}
				}
				if !strings.Contains(output, "permissions have NOT yet been checked") {
					t.Fatal("credential import claims permissions were verified")
				}
				if err := w.cleanupSessionCredentials(); err != nil {
					t.Fatal(err)
				}
				for path, before := range originals {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("source credential file changed")
					}
				}
			})
		}
	}
}

func TestR2InboxProfileFailurePreservesDraft(t *testing.T) {
	for _, kind := range []string{"same-key", "malformed", "empty-profile", "missing-file", "public-file", "cancel", "file-eof", "profile-eof", "decline-save"} {
		t.Run(kind, func(t *testing.T) {
			w, paths, answers := r2ProfileWizardFixture(t, false)
			w.d.Credentials, w.d.R2Parent, w.d.R2Control = "/retained/aws", "/retained/parent", "/retained/control"
			before, err := json.Marshal(w.d)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(w.draftPath, before, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "same-key", "malformed", "empty-profile":
				raw := r2TestProfile("inbox", strings.Repeat("b", 32), strings.Repeat("e", 64))
				if kind == "malformed" {
					raw += "[inbox]\n"
				} else if kind == "empty-profile" {
					raw = "[inbox]\n"
				}
				if err := os.WriteFile(paths[1], []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-file":
				if err := os.Remove(paths[1]); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(paths[1], 0644); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				answers = append(answers[:9], "0")
			case "file-eof":
				answers = answers[:10]
			case "profile-eof":
				answers = answers[:11]
			case "decline-save":
				answers[13] = "NO"
			}
			setR2Answers(w, answers)
			if err := w.setupR2(); err == nil {
				t.Fatal("incomplete or invalid setup succeeded")
			}
			after, _ := json.Marshal(w.d)
			saved, err := os.ReadFile(w.draftPath)
			if err != nil || !bytes.Equal(before, after) || !bytes.Equal(before, saved) {
				t.Fatal("failed setup changed the retained draft")
			}
			if _, err := os.Stat(w.credentialRoot); !os.IsNotExist(err) {
				t.Fatal("failed setup staged credentials")
			}
		})
	}
}

func TestR2InboxCredentialScalarFilesAndCancelNamedProfile(t *testing.T) {
	for _, kind := range []string{"scalar-files", "cancel-named-profile"} {
		t.Run(kind, func(t *testing.T) {
			w := setupFixture(t)
			dir := t.TempDir()
			id, secret := strings.Repeat("d", 32), strings.Repeat("e", 64)
			var answers []string
			if kind == "scalar-files" {
				idPath, secretPath := filepath.Join(dir, "id"), filepath.Join(dir, "secret")
				for path, value := range map[string]string{idPath: id, secretPath: secret} {
					if err := os.WriteFile(path, []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
				answers = []string{"2", "2", idPath, "2", secretPath}
			} else {
				path := filepath.Join(dir, "profiles")
				if err := os.WriteFile(path, []byte(r2TestProfile("cancel", id, secret)), 0600); err != nil {
					t.Fatal(err)
				}
				answers = []string{"1", path, "0"}
			}
			setR2Answers(&w, answers)
			gotID, gotSecret, err := w.inboxR2Credential()
			if err != nil || gotID != id || gotSecret != secret {
				t.Fatal("inbox credential selection failed", err)
			}
		})
	}
}
