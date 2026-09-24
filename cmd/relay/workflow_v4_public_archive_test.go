package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/verification"
)

func TestWorkflowV4RetainedArchiveMustMatchCurrentSignedInventory(t *testing.T) {
	expected := verification.Manifest{
		Schema: verification.Schema, CeremonyID: "sha256:" + strings.Repeat("a", 64), DefinitionSHA256: strings.Repeat("b", 64), ReleaseKeyID: "signer",
		Inputs:   map[string]string{"ceremony": "ceremony/public/ceremony.json"},
		Decision: &verification.Decision{Record: "ceremony/public/decision/decision.json", Signatures: []string{"ceremony/public/decision/coordinator.sig"}, EvidenceRoot: "ceremony/public/decision/evidence"},
		Files:    []verification.File{{Path: "ceremony/public/ceremony.json", Size: 10, SHA256: strings.Repeat("b", 64)}, {Path: "ceremony/public/decision/decision.json", SHA256: workflowV4ZeroSHA256}},
	}
	actual := expected
	actual.Files = append([]verification.File(nil), expected.Files...)
	actual.Files[1].Size = 20
	actual.Files[1].SHA256 = strings.Repeat("c", 64)
	if !workflowV4ArchiveMatchesExpected(actual, expected) {
		t.Fatal("exact signed files with filled decision digest rejected")
	}
	actual.Files[0].SHA256 = strings.Repeat("d", 64)
	if workflowV4ArchiveMatchesExpected(actual, expected) {
		t.Fatal("changed signed ceremony file accepted")
	}
	actual.Files[0] = expected.Files[0]
	actual.Decision = &verification.Decision{Record: "ceremony/public/decision/other.json"}
	if workflowV4ArchiveMatchesExpected(actual, expected) {
		t.Fatal("archive for another decision accepted")
	}
}

func TestWorkflowV4RetainedArchiveRejectsChangedPublicHandoffBytes(t *testing.T) {
	for _, name := range []string{"decision/decision.json", "decision/coordinator.sig", "decision/evidence/report.json", "coordinator-public-key.hex"} {
		t.Run(name, func(t *testing.T) {
			current := t.TempDir()
			local := filepath.Join(current, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(local, []byte("new public bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := workflowV4ArchivePrefix + name
			expected := verification.Manifest{Files: []verification.File{{Path: path, SHA256: workflowV4ZeroSHA256}}}
			actual := verification.Manifest{Files: []verification.File{{Path: path, Size: int64(len("old public bytes")), SHA256: workflowV4DigestBytes([]byte("old public bytes"))}}}
			if err := workflowV4ArchivePlaceholdersMatchCurrent(actual, expected, current); err == nil {
				t.Fatal("retained archive accepted old public bytes")
			}
			actual.Files[0].Size = int64(len("new public bytes"))
			actual.Files[0].SHA256 = workflowV4DigestBytes([]byte("new public bytes"))
			if err := workflowV4ArchivePlaceholdersMatchCurrent(actual, expected, current); err != nil {
				t.Fatalf("retained archive rejected matching public bytes: %v", err)
			}
		})
	}
}

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
