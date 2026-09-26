package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/state"
)

func TestDecisionPrepareEvidenceIncludesReleaseAndDetectsMutation(t *testing.T) {
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(work, "ceremony", "public")
	stage := filepath.Join(work, "workflow-v4", "decision", "staging")
	for _, dir := range []string{filepath.Join(public, "checkpoints"), filepath.Join(public, "final", "release"), filepath.Join(stage, "decision", "evidence")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	put := func(path, value string) state.ContentRef {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(value))
		name, _ := filepath.Rel(public, path)
		return state.ContentRef{Name: filepath.ToSlash(name), SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(value))}
	}
	refs := []state.ContentRef{
		put(filepath.Join(public, "checkpoints", "checkpoint.json"), "checkpoint"),
		put(filepath.Join(public, "final", "release", "candidate.json"), "candidate"),
	}
	if err := os.WriteFile(filepath.Join(stage, "decision", "evidence", "review.md"), []byte("review"), 0600); err != nil {
		t.Fatal(err)
	}
	root, verify, err := workflowV4DecisionPrepareEvidenceRoot(work, refs, stage)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"checkpoints/checkpoint.json", "final/release/candidate.json", "decision/evidence/review.md"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	sourceInfo, err := os.Stat(filepath.Join(public, "final", "release", "candidate.json"))
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Stat(filepath.Join(root, "final", "release", "candidate.json"))
	if err != nil || os.SameFile(sourceInfo, targetInfo) {
		t.Fatal("decision staging reused a release hardlink")
	}
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := workflowV4DecisionPrepareEvidenceRoot(work, append(refs, refs[0]), stage); err == nil {
		t.Fatal("duplicate authenticated path accepted")
	}
	if _, _, err := workflowV4DecisionPrepareEvidenceRoot(work, append(refs, state.ContentRef{Name: "decision/evidence/review.md", SHA256: refs[0].SHA256, Size: refs[0].Size}), stage); err == nil {
		t.Fatal("decision evidence collision accepted")
	}
	if err := os.WriteFile(filepath.Join(public, "final", "release", "candidate.json"), []byte("tampered!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verify(); err == nil {
		t.Fatal("source mutation after preparation was missed")
	}
}

func TestDecisionPrepareEvidenceCopyIsolatesCanonicalRelease(t *testing.T) {
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(work, "ceremony", "public")
	stage := filepath.Join(work, "workflow-v4", "decision", "staging", "decision", "evidence")
	if err := os.MkdirAll(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(public, "release.json")
	if err := os.WriteFile(input, []byte("signed release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "review.md"), []byte("review"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("signed release"))
	root, verify, err := workflowV4DecisionPrepareEvidenceRoot(work, []state.ContentRef{{Name: "release.json", SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: 14}}, filepath.Dir(filepath.Dir(stage)))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.WriteFile(filepath.Join(root, "release.json"), []byte("corrupt staged"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(mustReadDecisionTestFile(t, input)) != "signed release" || verify() == nil {
		t.Fatal("staged mutation changed canonical release or escaped recheck")
	}
}

func mustReadDecisionTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
