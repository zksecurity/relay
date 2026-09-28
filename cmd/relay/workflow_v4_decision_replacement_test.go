package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestDecisionReplacementGuideResumesSyntheticInterruptedRetirement(t *testing.T) {
	work, m := replacementFixture(t)
	trust, keys := t.TempDir(), t.TempDir()
	commit := strings.Repeat("a", 40)
	online := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys, ReleaseCommit: commit}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys, ReleaseCommit: commit}
	protocol := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production"}}
	snapshot := &storagefirst.SnapshotV4{}
	var output bytes.Buffer
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("8\n")), output: &output}
	if err := runWorkflowV4DecisionMenu(ui, online, signer, setupIdentity{}, protocol, snapshot); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Resume the confirmed unsigned-decision replacement") || !strings.Contains(output.String(), "Completed the previously confirmed unsigned decision retirement") {
		t.Fatalf("guide did not show and complete recovery:\n%s", output.String())
	}
	state, err := decisionReplacementReadState(work)
	if err != nil || state.Pending != nil || !state.Awaiting || len(state.Committed) != 1 {
		t.Fatalf("guide did not retain completed replacement: %+v, %v", state, err)
	}
	for _, item := range m.Items {
		if _, err := os.Lstat(filepath.Join(work, filepath.FromSlash(item.Source))); !os.IsNotExist(err) {
			t.Fatalf("active source remains after guide recovery: %s", item.Source)
		}
	}
}

// The test-only launcher executes the same coordinator decision menu reached
// from start.sh, with a synthetic pending replacement. It does not claim to
// authenticate a final release or qualify an attested production launcher.
func TestDecisionReplacementSyntheticStartSh(t *testing.T) {
	work, _ := replacementFixture(t)
	root := filepath.Dir(work)
	trust, keys := filepath.Join(root, "trust"), filepath.Join(root, "keys")
	for _, dir := range []string{trust, keys} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	argsPath := filepath.Join(root, "launcher-args.txt")
	wrapper := filepath.Join(root, "relay-test-wrapper")
	q := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	contents := fmt.Sprintf("#!/usr/bin/env bash\nset -euo pipefail\nprintf '%%s\\n' \"$@\" > %s\nexec %s -test.run '^TestDecisionReplacementStartShChild$' -test.v\n", q(argsPath), q(os.Args[0]))
	if err := os.WriteFile(wrapper, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	s := upgradeSelectionV2{Profile: guidedProfile{Name: "synthetic-decision", Role: "coordinator", Work: work, Trust: trust, Keys: keys, ReleaseCommit: strings.Repeat("a", 40)}}
	start := filepath.Join(root, "start.sh")
	if err := os.WriteFile(start, cleanExitOriginalStart(s, wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(start)
	cmd.Env = append(os.Environ(), "RELAY_SYNTHETIC_START_WORK="+work, "RELAY_SYNTHETIC_START_TRUST="+trust, "RELAY_SYNTHETIC_START_KEYS="+keys)
	cmd.Stdin = strings.NewReader("8\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic start.sh failed: %v\n%s", err, out)
	}
	for _, phrase := range []string{"Resume the confirmed unsigned-decision replacement", "Completed the previously confirmed unsigned decision retirement"} {
		if !strings.Contains(string(out), phrase) {
			t.Fatalf("start.sh did not reach replacement menu: %s\n%s", phrase, out)
		}
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"coordinator\nprepare\n", "--name\nsynthetic-decision\n", "--work\n" + work + "\n"} {
		if !strings.Contains(string(args), phrase) {
			t.Fatalf("start.sh routed unexpected arguments:\n%s", args)
		}
	}
	state, err := decisionReplacementReadState(work)
	if err != nil || state.Pending != nil || !state.Awaiting {
		t.Fatalf("start.sh did not retain completed replacement: %+v, %v", state, err)
	}
}

func TestDecisionReplacementStartShChild(t *testing.T) {
	work := os.Getenv("RELAY_SYNTHETIC_START_WORK")
	if work == "" {
		return
	}
	trust, keys := os.Getenv("RELAY_SYNTHETIC_START_TRUST"), os.Getenv("RELAY_SYNTHETIC_START_KEYS")
	commit := strings.Repeat("a", 40)
	online := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys, ReleaseCommit: commit}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys, ReleaseCommit: commit}
	protocol := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production"}}
	ui := &coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}
	snapshot := &storagefirst.SnapshotV4{}
	if err := runWorkflowV4DecisionMenu(ui, online, signer, setupIdentity{}, protocol, snapshot); err != nil {
		t.Fatal(err)
	}
}

func replacementFixture(t *testing.T) (string, decisionReplacementManifest) {
	t.Helper()
	work := t.TempDir()
	var err error
	work, err = filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	return work, replacementFixtureAt(t, work)
}

func replacementFixtureAt(t *testing.T, work string) decisionReplacementManifest {
	t.Helper()
	paths := decisionReplacementPaths(work)
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if filepath.Ext(path) == "" {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			path = filepath.Join(path, "record.json")
		}
		if err := os.WriteFile(path, []byte(path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := decisionReplacementManifest{Schema: decisionReplacementSchema, Generation: "01-test", Sequence: 1, CeremonyID: "ceremony", CandidateID: "candidate", CheckpointSHA256: "checkpoint", PolicySHA256: "policy", CoordinatorID: "coordinator", OldDecisionSHA256: decisionReplacementDigest([]byte("old")), Reason: "Correct an unsigned draft"}
	for _, path := range paths {
		files, _, err := decisionReplacementTree(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(work, path)
		if err != nil {
			t.Fatal(err)
		}
		m.Items = append(m.Items, decisionReplacementItem{Source: filepath.ToSlash(rel), Files: files})
	}
	if err := writeJSONNoReplace(filepath.Join(decisionReplacementRoot(work), m.Generation, "manifest.json"), m, 0600); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDecisionReplacementInterruptedMoves(t *testing.T) {
	for moved := 0; moved <= 4; moved++ {
		t.Run(string(rune('0'+moved)), func(t *testing.T) {
			work, m := replacementFixture(t)
			for _, item := range m.Items[:moved] {
				from := filepath.Join(work, filepath.FromSlash(item.Source))
				to := decisionReplacementRetiredPath(work, m, item.Source)
				if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(from, to); err != nil {
					t.Fatal(err)
				}
			}
			state, err := decisionReplacementReadState(work)
			if err != nil || state.Pending == nil {
				t.Fatalf("pending: %v, %v", state.Pending, err)
			}
			if err := decisionReplacementResume(work, *state.Pending); err != nil {
				t.Fatal(err)
			}
			state, err = decisionReplacementReadState(work)
			if err != nil || len(state.Committed) != 1 || !state.Awaiting {
				t.Fatalf("committed: %+v, %v", state, err)
			}
			for _, item := range m.Items {
				if _, err := os.Lstat(filepath.Join(work, filepath.FromSlash(item.Source))); !os.IsNotExist(err) {
					t.Fatalf("active source remained: %s", item.Source)
				}
				files, _, err := decisionReplacementTree(decisionReplacementRetiredPath(work, m, item.Source))
				if err != nil || !decisionReplacementSameFiles(files, item.Files) {
					t.Fatalf("retired bytes differ: %s: %v", item.Source, err)
				}
			}
		})
	}
}

func TestDecisionReplacementRejectsChangedAndDuplicateSources(t *testing.T) {
	work, m := replacementFixture(t)
	path := filepath.Join(work, filepath.FromSlash(m.Items[0].Source), "record.json")
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := decisionReplacementResume(work, m); err == nil {
		t.Fatal("accepted changed bytes")
	}
	if err := os.WriteFile(path, []byte(filepath.Dir(path)), 0600); err != nil {
		t.Fatal(err)
	}
	// A destination appearing before the corresponding source disappeared is
	// ambiguous even when it has the same bytes.
	to := decisionReplacementRetiredPath(work, m, m.Items[0].Source)
	if err := os.MkdirAll(to, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, "record.json"), []byte(path), 0600); err != nil {
		t.Fatal(err)
	}
	if err := decisionReplacementResume(work, m); err == nil {
		t.Fatal("accepted duplicate active and retired source")
	}
}

func TestDecisionReplacementRejectsHardlink(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.WriteFile(a, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decisionReplacementTree(a); err == nil || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("hardlink accepted: %v", err)
	}
}

func TestDecisionReplacementSecondGenerationAndDuplicateDigest(t *testing.T) {
	work, first := replacementFixture(t)
	if err := decisionReplacementResume(work, first); err != nil {
		t.Fatal(err)
	}
	for _, path := range decisionReplacementPaths(work) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if filepath.Ext(path) == "" {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			path = filepath.Join(path, "record.json")
		}
		if err := os.WriteFile(path, []byte("new "+path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	second := first
	second.Generation, second.Sequence, second.OldDecisionSHA256 = "02-test", 2, decisionReplacementDigest([]byte("new"))
	second.Items = nil
	for _, path := range decisionReplacementPaths(work) {
		files, _, err := decisionReplacementTree(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(work, path)
		if err != nil {
			t.Fatal(err)
		}
		second.Items = append(second.Items, decisionReplacementItem{Source: filepath.ToSlash(rel), Files: files})
	}
	manifestPath := filepath.Join(decisionReplacementRoot(work), second.Generation, "manifest.json")
	if err := writeJSONNoReplace(manifestPath, second, 0600); err != nil {
		t.Fatal(err)
	}
	state, err := decisionReplacementReadState(work)
	if err != nil || len(state.Committed) != 1 || state.Pending == nil {
		t.Fatalf("second pending: %+v, %v", state, err)
	}
	if err := decisionReplacementResume(work, second); err != nil {
		t.Fatal(err)
	}
	state, err = decisionReplacementReadState(work)
	if err != nil || len(state.Committed) != 2 || !state.Awaiting {
		t.Fatalf("second committed: %+v, %v", state, err)
	}
	second.OldDecisionSHA256 = first.OldDecisionSHA256
	if err := saveJSONAtomic(manifestPath, second); err != nil {
		t.Fatal(err)
	}
	if _, err := decisionReplacementReadState(work); err == nil {
		t.Fatal("duplicate retired decision digest accepted")
	}
}
