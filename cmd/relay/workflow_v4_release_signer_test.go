package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4ReleaseSigningUsesCurrentCheckpointNotEvidenceBundle(t *testing.T) {
	checkpoint := pairV4Test("checkpoints/final/review-1/checkpoint")
	bundle := pairV4Test("operational/evidence-bundle")
	got, err := workflowV4ReleaseReviewCheckpoint(checkpoint, &bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got != checkpoint {
		t.Fatalf("release checkpoint = %#v, want authenticated current head %#v", got, checkpoint)
	}
	if _, err := workflowV4ReleaseReviewCheckpoint(bundle, &bundle); err == nil {
		t.Fatal("operational evidence bundle accepted as the release-review checkpoint")
	}
	if _, err := workflowV4ReleaseReviewCheckpoint(checkpoint, (*transcript.SignedArtifactRefs)(nil)); err == nil {
		t.Fatal("missing operational evidence bundle accepted")
	}
}

func TestWorkflowV4ReleaseCommandsBindFrozenReviewAndSeparateOutput(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	online := guidedProfile{Work: work, Trust: trust, Keys: keys}
	signer := online
	head := pairV4Test("final/review")
	when := time.Date(2026, 9, 16, 6, 7, 8, 9, time.UTC)
	report := filepath.Join(work, "workflow-v4", "release", "review.json")
	packageDir := filepath.Join(work, "workflow-v4", "release", "release-package")
	review, err := workflowV4ReleaseReviewCommand(online, signer, head, report, when)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := workflowV4ReleaseSignCommand(online, signer, head, packageDir, "release-key", when)
	if err != nil {
		t.Fatal(err)
	}
	for command, wants := range map[string][]string{
		strings.Join(review, " "): {"release review-v4", "--checkpoint /work/ceremony/public/" + head.Record.Name, "--released-at " + when.Format(time.RFC3339Nano), "--out /work/workflow-v4/release/review.json"},
		strings.Join(sign, " "):   {"release sign", "--review-checkpoint /work/ceremony/public/" + head.Record.Name, "--operational-evidence-root /work/ceremony/public", "--release-signing-key /keys/signing.hex", "--signature-key-id release-key", "--release-dir /work/workflow-v4/release/release-package"},
	} {
		for _, want := range wants {
			if !strings.Contains(command, want) {
				t.Fatalf("command %q lacks %q", command, want)
			}
		}
	}
}

func TestWorkflowV4ReleaseFilesPreserveNestedNamesAndRejectSymlink(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{"manifest.json": "manifest", "operational/evidence.json": "evidence"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	inventory, _, paths, err := workflowV4ReleaseFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 2 || paths["operational/evidence.json"] == "" {
		t.Fatalf("nested release inventory = %#v", inventory)
	}
	if err := os.Symlink(filepath.Join(root, "manifest.json"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := workflowV4ReleaseFiles(root); err == nil {
		t.Fatal("release package symlink accepted")
	}
}

func TestWorkflowV4FinalReleaseCheckpointUsesOnlyProtocolBootstraps(t *testing.T) {
	paths := map[string]string{
		"manifest.json":           "/release/manifest.json",
		"manifest.sig":            "/release/manifest.sig",
		"setup-transcript.json":   "/release/setup-transcript.json",
		"manifest-public-key.hex": "/release/manifest-public-key.hex",
		"checksums.sha256":        "/release/checksums.sha256",
		"ownership.pk":            "/release/ownership.pk",
	}
	evidence, err := workflowV4FinalReleaseEvidence(paths)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/release/checksums.sha256", "/release/manifest-public-key.hex", "/release/setup-transcript.json"}
	if strings.Join(evidence, "\n") != strings.Join(want, "\n") {
		t.Fatalf("checkpoint evidence = %q, want %q", evidence, want)
	}
	delete(paths, "setup-transcript.json")
	if _, err := workflowV4FinalReleaseEvidence(paths); err == nil {
		t.Fatal("missing final release bootstrap accepted")
	}
}

func TestWorkflowV4ReleaseSignerRecognizesProofToolPackageLayout(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "workflow-v4", "release", workflowV4ReleasePackageDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "manifest.sig", workflowV4ReleaseManifestPublicFile, workflowV4ReleaseTranscriptFile, workflowV4ReleaseChecksumsFile} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	progress, err := workflowV4ReleaseSignerProgressFor(work)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.PackageReady {
		t.Fatal("complete proof-tool release package was not recognized")
	}
}
