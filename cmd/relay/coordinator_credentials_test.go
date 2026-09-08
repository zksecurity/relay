package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func credentialMigrationFixture(t *testing.T) (*coordinatorWizard, string, guidedProfile) {
	t.Helper()
	dir := privateRoleTestDir(t)
	p := guidedProfile{Schema: guidedSchema, Name: "migration", Role: "coordinator", Image: "sha256:" + strings.Repeat("a", 64), Platform: "linux/arm64"}
	for name, target := range map[string]*string{"work": &p.Work, "trust": &p.Trust, "keys": &p.Keys} {
		*target = filepath.Join(dir, name)
		if err := os.Mkdir(*target, 0700); err != nil {
			t.Fatal(err)
		}
	}
	w := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("UPDATE CREDENTIAL REFERENCES\n")), output: new(bytes.Buffer)}
	for name, target := range map[string]*string{"aws": &w.d.Credentials, "parent": &w.d.R2Parent, "control": &w.d.R2Control} {
		*target = filepath.Join(dir, name)
		if err := os.WriteFile(*target, []byte("synthetic credential\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := setupWriteNew(filepath.Join(dir, "profile.json"), p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "workflow"), 0700); err != nil {
		t.Fatal(err)
	}
	return w, dir, p
}

func TestCredentialMigrationPreservesCoreAndHistory(t *testing.T) {
	w, dir, p := credentialMigrationFixture(t)
	path := filepath.Join(dir, "workflow", "state.json")
	s := roleFlowState{Schema: roleFlowSchema, Profile: p, Attempts: []flowAttempt{{ID: "previous", Stage: "storage", Task: "check", Status: "succeeded", FinishedAt: "2026-09-08T00:00:00Z"}}}
	if err := setupWriteNew(path, s); err != nil {
		t.Fatal(err)
	}
	if err := w.refreshWorkflowCredentials(dir, p); err != nil {
		t.Fatal(err)
	}
	got, err := readGuidedProfile(filepath.Join(dir, "profile.json"), p.Name, p.Role)
	if err != nil || !sameProfileExceptCredentials(got, p) || got.R2Parent != w.d.R2Parent {
		t.Fatalf("profile: %+v %v", got, err)
	}
	var after roleFlowState
	if err := setupReadJSON(path, &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Attempts) != 2 || !reflect.DeepEqual(after.Attempts[0], s.Attempts[0]) || !reflect.DeepEqual(after.Profile, got) {
		t.Fatal("history or profile changed incorrectly")
	}
}

func TestCredentialMigrationRejectsUncertainAttempt(t *testing.T) {
	for _, status := range []string{"running", "failed"} {
		t.Run(status, func(t *testing.T) {
			w, dir, p := credentialMigrationFixture(t)
			s := roleFlowState{Schema: roleFlowSchema, Profile: p, Attempts: []flowAttempt{{Stage: "storage", Task: "check", Status: status}}}
			if err := setupWriteNew(filepath.Join(dir, "workflow", "state.json"), s); err != nil {
				t.Fatal(err)
			}
			if err := w.refreshWorkflowCredentials(dir, p); !errors.Is(err, errCredentialsNeedRecovery) {
				t.Fatal(err)
			}
			got, err := readGuidedProfile(filepath.Join(dir, "profile.json"), p.Name, p.Role)
			if err != nil || !reflect.DeepEqual(got, p) {
				t.Fatal("uncertain profile changed")
			}
		})
	}
}

func TestCredentialMigrationReconcilesPartialCheckpoint(t *testing.T) {
	w, dir, old := credentialMigrationFixture(t)
	current := old
	current.Credentials, current.R2Parent, current.R2Control = w.d.Credentials, w.d.R2Parent, w.d.R2Control
	if err := saveJSONAtomic(filepath.Join(dir, "profile.json"), current); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "workflow", "state.json")
	if err := setupWriteNew(path, roleFlowState{Schema: roleFlowSchema, Profile: old}); err != nil {
		t.Fatal(err)
	}
	if err := w.refreshWorkflowCredentials(dir, current); err != nil {
		t.Fatal(err)
	}
	var after roleFlowState
	if err := setupReadJSON(path, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.Profile, current) {
		t.Fatal("partial checkpoint was not reconciled")
	}
}

func TestCredentialMigrationRefusesActiveProfile(t *testing.T) {
	w, dir, p := credentialMigrationFixture(t)
	lock, err := acquireParticipantRunLock(filepath.Join(dir, "profile.json"), filepath.Join(dir, "activity"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	if err := w.refreshWorkflowCredentials(dir, p); err == nil {
		t.Fatal("changed active profile")
	}
}
