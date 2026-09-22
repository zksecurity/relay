package main

// These scenarios use the actual source/candidate executables and signed tiny
// ceremony. Authorization is test-only; no production skip or failpoint exists.
import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/upgrade"
)

func runCleanExitScenario(t *testing.T, scenario string) {
	t.Helper()
	if os.Getenv("RELAY_UPGRADE_QUALIFICATION_REQUEST") == "" {
		t.Skip("exact source and candidate assets required")
	}
	var request upgrade.QualificationRequest
	if err := setupReadJSON(os.Getenv("RELAY_UPGRADE_QUALIFICATION_REQUEST"), &request); err != nil {
		t.Fatal(err)
	}
	if !upgrade.IsCleanExitQualification(request.QualificationSchema) {
		t.Fatal("completed-step qualification request required")
	}
	t.Setenv("RELAY_UPGRADE_LOCAL_STORAGE", "1")
	t.Setenv("RELAY_UPGRADE_CLEAN_SCENARIO", scenario)
	TestUpgradeLocalTwoPhaseJourney(t)
}

func TestUpgradeCleanExitContinuation(t *testing.T) { runCleanExitScenario(t, "continuation") }
func TestUpgradeCleanExitInterruption(t *testing.T) { runCleanExitScenario(t, "interruption") }
func TestUpgradeCleanExitRefusal(t *testing.T)      { runCleanExitScenario(t, "refusal") }

// Hash private files without emitting their contents or names in public reports.
func cleanExitTree(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			h, err := setupFileHash(path)
			if err != nil {
				return err
			}
			st, err := os.Stat(path)
			if err != nil {
				return err
			}
			result[path] = fmt.Sprintf("%s:%o", h, st.Mode().Perm())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func cleanExitOriginalStart(s upgradeSelectionV2, source string) []byte {
	p := s.Profile
	q := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	return []byte(strings.Join([]string{"#!/usr/bin/env bash", "set -euo pipefail", "relay_launcher=" + q(source), "ceremony_name=" + q(p.Name), "ceremony_role=" + q(p.Role), "ceremony_release=" + q("role-images-"+p.ReleaseCommit), "ceremony_work=" + q(p.Work), "ceremony_trust=" + q(p.Trust), "ceremony_keys=" + q(p.Keys), `if [[ "$ceremony_role" == coordinator ]]; then`, `  exec "$relay_launcher" coordinator prepare --name "$ceremony_name" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, `fi`, `exec "$relay_launcher" ceremony prepare --name "$ceremony_name" --role "$ceremony_role" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, ""}, "\n"))
}

func exerciseCleanExitScenario(t *testing.T, f upgradeRealFixture, s upgradeSelectionV2, scenario string) {
	t.Helper()
	d := f.request.Declaration
	// Test-only approval origin, deliberately distinct from the tested app.
	s.ApprovalRelease = "role-images-" + strings.Repeat("c", 40)
	s.PreviousStart = cleanExitOriginalStart(s, f.request.Predecessors[d.SourceApp])
	if !upgradeV2GeneratedStart(s.PreviousStart, s.Profile) {
		t.Fatal("invalid installer fixture")
	}
	if err := os.WriteFile(s.StartPath, s.PreviousStart, 0700); err != nil {
		t.Fatal(err)
	}
	ceremonyBefore := cleanExitTree(t, filepath.Join(s.Profile.Work, "ceremony"), s.Profile.Trust, s.Profile.Keys)
	if scenario == "refusal" {
		refuse := func(candidate upgradeSelectionV2) {
			before := cleanExitTree(t, s.Profile.Work, s.Profile.Trust, s.Profile.Keys, s.SettingsRoot)
			if err := upgradeV2Activate(candidate, ""); err == nil {
				t.Fatal("unsafe update succeeded")
			}
			if !reflect.DeepEqual(before, cleanExitTree(t, s.Profile.Work, s.Profile.Trust, s.Profile.Keys, s.SettingsRoot)) {
				t.Fatal("refused update changed files")
			}
			if raw, err := os.ReadFile(s.StartPath); err != nil || string(raw) != string(s.PreviousStart) {
				t.Fatal("old start script changed")
			}
		}
		// A retained intent whose output was never accepted must block activation.
		intents, err := filepath.Glob(filepath.Join(s.Profile.Work, "workflow-v4/coordinator/*/*-intent.json"))
		if err != nil || len(intents) == 0 {
			t.Fatal("real coordinator intent missing", err)
		}
		var intent workflowV4CoordinatorIntent
		if err := readWorkflowV4JSON(intents[0], &intent); err != nil {
			t.Fatal(err)
		}
		intent.OutputDir = filepath.Join(s.Profile.Work, "ceremony/public/checkpoints/uncompleted")
		pending := filepath.Join(filepath.Dir(intents[0]), "uncompleted-intent.json")
		if err := writeJSONNoReplace(pending, intent, 0600); err != nil {
			t.Fatal(err)
		}
		refuse(s)
		if err := os.Remove(pending); err != nil {
			t.Fatal(err)
		} // test-created fault only
		wrong := s
		changed := d
		changed.Protocol = "unsupported-protocol"
		wrong.Declaration, _ = json.Marshal(changed)
		refuse(wrong)
		wrong = s
		wrong.Profile.Platform = "linux/unsupported"
		refuse(wrong)
	}
	if scenario == "interruption" {
		input := filepath.Join(t.TempDir(), "selection.json")
		if err := writeJSONNoReplace(input, s, 0600); err != nil {
			t.Fatal(err)
		}
		run := func(stage string) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestUpgradeCleanExitChild$")
			cmd.Env = append(os.Environ(), "RELAY_CLEAN_CHILD_INPUT="+input, "RELAY_CLEAN_CHILD_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatalf("wrong interruption result: %v %s", err, out)
			}
		}
		run("before-selection")
		if _, err := os.Stat(upgradeV2PointerPath(s.Profile.Work)); !os.IsNotExist(err) {
			t.Fatal("selected before publication")
		}
		if raw, err := os.ReadFile(s.StartPath); err != nil || string(raw) != string(s.PreviousStart) {
			t.Fatal("old launcher no longer selected")
		}
		run("after-selection")
		if raw, err := os.ReadFile(s.StartPath); err != nil || string(raw) != string(s.PreviousStart) {
			t.Fatal("script unexpectedly changed before repair")
		}
		run("after-repair")
		run("after-repair") // repeated repair is idempotent, not another activation
	} else {
		if err := upgradeV2Activate(s, ""); err != nil {
			t.Fatal(err)
		}
		if err := upgradeV2FinishStart(s); err != nil {
			t.Fatal(err)
		}
	}
	if raw, err := os.ReadFile(s.StartPath); err != nil || string(raw) != string(upgradeV2StartBytes(s)) {
		t.Fatal("new entry point not installed")
	}
	// Exercise the actual target binary's selected-state reader and same-target
	// repair branch. It must not fetch new approval or replay ceremony work.
	cmd := exec.Command(f.request.Candidate, "ceremony", "upgrade", s.Profile.Name, "--role", s.Profile.Role, "--settings-root", s.SettingsRoot, "--release", "role-images-"+d.TargetApp, "--approval-release", s.ApprovalRelease)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("candidate selection repair failed: %v %s", err, out)
	}
	if history, _, err := upgradeV2ReadHistory(s.Profile.Work); err != nil || len(history) != 1 {
		t.Fatal("update repeated or lost", err)
	}
	if !reflect.DeepEqual(ceremonyBefore, cleanExitTree(t, filepath.Join(s.Profile.Work, "ceremony"), s.Profile.Trust, s.Profile.Keys)) {
		t.Fatal("update changed signed ceremony or keys")
	}
}

// Abrupt subprocess exit at real durable boundaries. Compiled only into tests.
func TestUpgradeCleanExitChild(t *testing.T) {
	input := os.Getenv("RELAY_CLEAN_CHILD_INPUT")
	if input == "" {
		t.Skip("private subprocess only")
	}
	var s upgradeSelectionV2
	if err := readWorkflowV4JSON(input, &s); err != nil {
		t.Fatal(err)
	}
	switch os.Getenv("RELAY_CLEAN_CHILD_STAGE") {
	case "before-selection":
	case "after-selection":
		if err := upgradeV2Activate(s, ""); err != nil {
			t.Fatal(err)
		}
	case "after-repair":
		if err := upgradeV2FinishStart(s); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown interruption boundary")
	}
	os.Exit(73)
}
