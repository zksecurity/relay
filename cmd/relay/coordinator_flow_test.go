package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateLegacyCoordinatorWorkflowReusesEnrollmentAlias(t *testing.T) {
	root := t.TempDir()
	name := "demo"
	legacyName := name + "-workflow"
	legacyDir, err := guidedDirectory(root, legacyName, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(legacyDir, "workflow"), 0700); err != nil {
		t.Fatal(err)
	}
	profile := guidedProfile{Schema: guidedSchema, Name: legacyName, Role: "coordinator", ReleaseCommit: strings.Repeat("a", 40), Image: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64", Work: filepath.Join(root, "work"), Trust: filepath.Join(root, "trust"), Keys: filepath.Join(root, "keys")}
	if err := writeJSONNoReplace(filepath.Join(legacyDir, "profile.json"), profile, 0600); err != nil {
		t.Fatal(err)
	}
	state := roleFlowState{Schema: roleFlowSchema, Name: legacyName, Role: "coordinator", Profile: profile, Values: map[string]string{}}
	if err := writeJSONNoReplace(filepath.Join(legacyDir, "workflow", "state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacyCoordinatorWorkflow(root, name); err != nil {
		t.Fatal(err)
	}
	currentDir, err := guidedDirectory(root, name, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	got, err := readGuidedProfile(filepath.Join(currentDir, "profile.json"), name, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != name {
		t.Fatalf("profile name = %q, want %q", got.Name, name)
	}
	var migrated roleFlowState
	if err := setupReadJSON(filepath.Join(currentDir, "workflow", "state.json"), &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Name != name || migrated.Profile.Name != name {
		t.Fatalf("workflow was not retargeted: %#v", migrated)
	}
	if _, err := os.Stat(filepath.Join(currentDir, "profile.json.pre-custody-v1.bak")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(currentDir, "workflow", "state.json.pre-custody-v1.bak")); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateLegacyCoordinatorWorkflowRefusesTwoProfiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"demo", "demo-workflow"} {
		dir, err := guidedDirectory(root, name, "coordinator")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		p := guidedProfile{Schema: guidedSchema, Name: name, Role: "coordinator", ReleaseCommit: strings.Repeat("a", 40)}
		if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), p, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateLegacyCoordinatorWorkflow(root, "demo"); err == nil || !strings.Contains(err.Error(), "both current and older") {
		t.Fatalf("ambiguous profiles were accepted: %v", err)
	}
}
