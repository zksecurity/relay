package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWorkflowV4DecisionArchiveInventoryIsClosed(t *testing.T) {
	root := t.TempDir()
	decision := filepath.Join(root, "decision")
	if err := os.MkdirAll(filepath.Join(decision, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(decision, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("decision.json", `{"schema":"proof-tool-mpc-production-decision-v5","source_release":{"verification_report":{"name":"decision/evidence/source.json","digest":{"sha256":"sha256:`+strings.Repeat("a", 64)+`"}}}}`)
	write("coordinator.sig", "signature")
	write("evidence/source.json", "public evidence")
	files, signatures, err := workflowV4DecisionArchiveFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"decision/coordinator.sig", "decision/decision.json", "decision/evidence/source.json"}) || !slices.Equal(signatures, []string{"decision/coordinator.sig"}) {
		t.Fatalf("unexpected selected files: %v, signatures: %v", files, signatures)
	}
	write("evidence/extra.json", "unreviewed")
	if _, _, err := workflowV4DecisionArchiveFiles(root); err == nil {
		t.Fatal("unreferenced evidence was accepted")
	}
	if err := os.Remove(filepath.Join(decision, "evidence", "extra.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(decision, "decision.json"), filepath.Join(decision, "evidence", "extra.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := workflowV4DecisionArchiveFiles(root); err == nil {
		t.Fatal("symlink in public decision handoff was accepted")
	}
}
