package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadinessExplainsMissingInputWithoutClaimingVerification(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	task := flowTask{ID: "audit", Fields: []flowField{ff("record", "Signed audit", "/work/audit.json")}}
	if got := f.readiness(task); got.Status != "Waiting" || !strings.Contains(got.summary(), "audit.json") {
		t.Fatal(got)
	}
	if err := os.WriteFile(filepath.Join(f.state.Profile.Work, "audit.json"), []byte("unverified"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := f.readiness(task); got.Status != "Ready to review inputs" {
		t.Fatal(got)
	}
}

func TestEvidenceDirectoryChangesInvalidateProgress(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	root := filepath.Join(f.state.Profile.Work, "bundle")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{Fields: []flowField{ff("candidate-bundle", "Candidate", "/work/bundle")}}
	bindings, err := f.captureDirectories(task, []string{"--candidate-bundle", "/work/bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.checkDirectoryBindings(bindings); err == nil {
		t.Fatal("bundle addition unnoticed")
	}
}

func TestTranscriptGrowthPreservesEarlierEvidenceButReplacementDoesNot(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	root := filepath.Join(f.state.Profile.Work, "public")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "chain-0000.json")
	if err := os.WriteFile(first, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{Fields: []flowField{ff("transcript-dir", "Transcript", "/work/public")}}
	bindings, err := f.captureDirectories(task, []string{"--transcript-dir", "/work/public"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chain-0001.json"), []byte("next"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.checkDirectoryBindings(bindings); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.checkDirectoryBindings(bindings); err == nil {
		t.Fatal("replacement unnoticed")
	}
}

func TestEvidenceTreeRefusesKeysAndSymlinks(t *testing.T) {
	for _, kind := range []string{"key", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			var err error
			if kind == "key" {
				err = os.WriteFile(filepath.Join(root, "signing.hex"), []byte("fixture-not-a-key"), 0600)
			} else {
				err = os.Symlink(t.TempDir(), filepath.Join(root, "linked"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := flowTreeHash(root); err == nil {
				t.Fatal("unsafe evidence tree accepted")
			}
		})
	}
}

func TestSuccessfulOutputDeletionRequiresRecovery(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	path := filepath.Join(f.state.Profile.Work, "audit.json")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{ID: "audit", Fields: []flowField{ff("out", "Public audit", "/work/audit.json")}}
	a := flowAttempt{Task: "audit", Stage: "test", Status: "succeeded"}
	if err := f.bindSuccessfulOutputs(task, []string{"--out", "/work/audit.json"}, &a); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f.state.Attempts = append(f.state.Attempts, a)
	if got := f.readiness(task); got.Status != "Needs attention" {
		t.Fatal(got)
	}
}

func TestPublicOutputBindingNeverReadsGrant(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	task := flowTask{Command: []string{"relay", "coordinator", "grant"}, Fields: []flowField{ff("out", "Secret grant", "/work/missing.grant.json")}}
	a := flowAttempt{}
	if err := f.bindSuccessfulOutputs(task, []string{"--out", "/work/missing.grant.json"}, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.InputBindings) != 0 || len(a.DirectoryBindings) != 0 {
		t.Fatal("grant was bound as public evidence")
	}
}

func TestArtifactHandoffRequiresAndBindsPublicFiles(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	f.state.Role = "release-signer"
	task := handoff("handoff", "Transfer signed release", "Public files only")
	if _, err := f.handoffBindings(task); err == nil {
		t.Fatal("missing release allowed a handoff report")
	}
	root := filepath.Join(f.state.Profile.Work, "release")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "manifest.sig"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bindings, err := f.handoffBindings(task)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.checkAttemptEvidence(&flowAttempt{Status: "reported", InputBindings: bindings}); err == nil {
		t.Fatal("changed handoff not noticed")
	}
}
