package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4DirectReleaseImportClosesInventoryAndRetainsExistingWork(t *testing.T) {
	work := t.TempDir()
	source := filepath.Join(work, "handoff", "release")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"manifest.json":           []byte("public manifest"),
		"manifest.sig":            []byte("public signature"),
		"manifest-public-key.hex": []byte("public key"),
	}
	var checksums strings.Builder
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(source, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&checksums, "%x  %s\n", sha256.Sum256(value), name)
	}
	if err := os.WriteFile(filepath.Join(source, workflowV4ReleaseChecksumsFile), []byte(checksums.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := guidedProfile{Role: "coordinator", Work: work, Trust: t.TempDir()}
	previous := workflowV4ChildExecutor
	workflowV4ChildExecutor = func([]string) error { return nil }
	defer func() { workflowV4ChildExecutor = previous }()
	if err := os.WriteFile(filepath.Join(source, "signing.hex"), []byte("should never enter public release"), 0o600); err != nil {
		t.Fatal(err)
	}
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("IMPORT SIGNED RELEASE\n")), output: io.Discard}
	if err := runWorkflowV4ImportReleasePackage(ui, profile, source, "release-key"); err == nil {
		t.Fatal("unlisted file imported into the public release")
	}
	if err := os.Remove(filepath.Join(source, "signing.hex")); err != nil {
		t.Fatal(err)
	}
	ui.input = bufio.NewReader(strings.NewReader("IMPORT SIGNED RELEASE\n"))
	if err := runWorkflowV4ImportReleasePackage(ui, profile, source, "release-key"); err != nil {
		t.Fatal(err)
	}
	retained := workflowV4CoordinatorReleaseImportPath(work)
	if _, err := os.Stat(filepath.Join(retained, "manifest.json")); err != nil {
		t.Fatal("verified public package was not retained", err)
	}
	if err := runWorkflowV4ImportReleasePackage(ui, profile, retained, "release-key"); err == nil {
		t.Fatal("retained import silently replaced")
	}
}

func TestWorkflowV4DirectReleasePreservesOlderGrantPath(t *testing.T) {
	v5 := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production"}}
	if !workflowV4CoordinatorDirectRelease(v5) {
		t.Fatal("V5 production coordinator did not select direct handoff")
	}
	v4 := v5
	v4.DefinitionSchema = "proof-tool-mpc-ceremony-definition-v4"
	if workflowV4CoordinatorDirectRelease(v4) {
		t.Fatal("older frozen ceremony was changed to direct handoff")
	}
	work := t.TempDir()
	if retained, err := workflowV4RetainedReleaseGrantExists(work); err != nil || retained {
		t.Fatalf("fresh workspace has a release grant: %v %v", retained, err)
	}
	dir := filepath.Join(work, "workflow-v4", "coordinator", "release", "grants")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old-attempt.json"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if retained, err := workflowV4RetainedReleaseGrantExists(work); err != nil || !retained {
		t.Fatalf("retained grant was ignored: %v %v", retained, err)
	}
}
