package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	workflowV4ReleasePackageDir         = "release-package"
	workflowV4ReleaseTranscriptFile     = "setup-transcript.json"
	workflowV4ReleaseChecksumsFile      = "checksums.sha256"
	workflowV4ReleaseManifestPublicFile = "manifest-public-key.hex"
)

type workflowV4ReleaseSignerProgress struct {
	PackageReady bool
	PackageDir   string
	ReviewReport string
}

func workflowV4ReleaseSignerProgressFor(work string) (workflowV4ReleaseSignerProgress, error) {
	base := filepath.Join(work, "workflow-v4", "release")
	p := workflowV4ReleaseSignerProgress{PackageDir: filepath.Join(base, workflowV4ReleasePackageDir), ReviewReport: filepath.Join(base, "review.json")}
	info, err := os.Lstat(p.PackageDir)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return p, errors.New("retained release package path is not a real directory")
	}
	for _, name := range []string{"manifest.json", "manifest.sig", workflowV4ReleaseManifestPublicFile, workflowV4ReleaseTranscriptFile, workflowV4ReleaseChecksumsFile} {
		if !regularPreparationFile(filepath.Join(p.PackageDir, name)) {
			return p, errors.New("retained release package is incomplete; preserve it for inspection")
		}
	}
	p.PackageReady = true
	return p, nil
}

func runWorkflowV4ReleaseSignerAction(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, online, signer guidedProfile, identity setupIdentity, progress workflowV4ReleaseSignerProgress) error {
	stateView, err := snapshot.State()
	if err != nil {
		return err
	}
	if stateView.Progress.ReleaseReview == nil || stateView.Progress.FinalRelease != nil {
		return errors.New("release signing requires the current frozen review and no recorded final release")
	}
	expected, err := workflowV4ExpectedEnrollment(protocol, identity.ID)
	if err != nil {
		return err
	}
	if expected.Role != "release-signer" || expected.Identity.KeyID != identity.KeyID {
		return errors.New("local release signer differs from the signed ceremony assignment")
	}
	if !progress.PackageReady {
		return runWorkflowV4ReleaseSigning(ui, snapshot, online, signer, expected, progress)
	}
	return runWorkflowV4ReleaseUpload(ui, snapshot, protocol, config, online, identity.ID, expected.Identity.KeyID, progress)
}

func runWorkflowV4ReleaseSigning(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, online, signer guidedProfile, expected transcript.ExpectedEnrollment, progress workflowV4ReleaseSignerProgress) error {
	stateView, err := snapshot.State()
	if err != nil {
		return err
	}
	head := stateView.Progress.ReleaseReview
	if head == nil {
		return errors.New("release review is not present")
	}
	if err := os.MkdirAll(filepath.Dir(progress.ReviewReport), 0o700); err != nil {
		return err
	}
	releasedAt := time.Now().UTC()
	if regularPreparationFile(progress.ReviewReport) {
		raw, err := readTesseraRegularFile(progress.ReviewReport, 64<<20, false)
		if err != nil {
			return err
		}
		var retained struct {
			ReleasedAt string `json:"released_at"`
		}
		if err := json.Unmarshal(raw, &retained); err != nil {
			return errors.New("retained release review report is invalid; preserve it for inspection")
		}
		releasedAt, err = time.Parse(time.RFC3339Nano, retained.ReleasedAt)
		if err != nil || releasedAt.Location() != time.UTC {
			return errors.New("retained release review time is invalid; preserve it for inspection")
		}
	} else {
		command, err := workflowV4ReleaseReviewCommand(online, signer, *head, progress.ReviewReport, releasedAt)
		if err != nil {
			return err
		}
		if err := runWorkflowV4ProfileCommand(online, command, false); err != nil {
			return err
		}
	}
	if err := ui.confirm("The approved proof-tool verified the exact coordinator review checkpoint and its bound full replay. Sign only this exact package", "SIGN RELEASE PACKAGE"); err != nil {
		return err
	}
	command, err := workflowV4ReleaseSignCommand(online, signer, *head, progress.PackageDir, expected.Identity.KeyID, releasedAt)
	if err != nil {
		return err
	}
	if err := runWorkflowV4ProfileCommand(signer, command, false); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Signed release package created and self-verified at %s. It is still private and has not been accepted or published.\n", progress.PackageDir)
	return nil
}

func workflowV4ReleaseReviewCommand(online, signer guidedProfile, head transcript.SignedArtifactRefs, out string, releasedAt time.Time) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapWork := func(path string) (string, error) { return pathWithin(online.Work, path, "/work") }
	ceremony, err := mapWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySig, _ := mapWork(filepath.Join(root, "ceremony.sig"))
	artifactRoot, _ := mapWork(root)
	checkpoint, err := mapWork(filepath.Join(root, filepath.FromSlash(head.Record.Name)))
	if err != nil {
		return nil, err
	}
	checkpointSig, _ := mapWork(filepath.Join(root, filepath.FromSlash(head.Signature.Name)))
	bundle, _ := mapWork(filepath.Join(root, "operational", "evidence-bundle.json"))
	bundleSig, _ := mapWork(filepath.Join(root, "operational", "evidence-bundle.sig"))
	output, err := mapWork(out)
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(online.Trust, filepath.Join(online.Trust, "coordinator-public-key.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"mpc-ceremony", "release", "review-v4", "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey, "--artifact-root", artifactRoot, "--checkpoint", checkpoint, "--checkpoint-signature", checkpointSig, "--operational-bundle", bundle, "--operational-bundle-signature", bundleSig, "--released-at", releasedAt.Format(time.RFC3339Nano), "--out", output}, nil
}

func workflowV4ReleaseSignCommand(online, signer guidedProfile, head transcript.SignedArtifactRefs, releaseDir, keyID string, releasedAt time.Time) ([]string, error) {
	root := filepath.Join(online.Work, "ceremony", "public")
	mapSignerWork := func(path string) (string, error) { return pathWithin(signer.Work, path, "/work") }
	ceremony, err := mapSignerWork(filepath.Join(root, "ceremony.json"))
	if err != nil {
		return nil, err
	}
	ceremonySig, _ := mapSignerWork(filepath.Join(root, "ceremony.sig"))
	artifactRoot, _ := mapSignerWork(root)
	checkpoint, err := mapSignerWork(filepath.Join(root, filepath.FromSlash(head.Record.Name)))
	if err != nil {
		return nil, err
	}
	checkpointSig, _ := mapSignerWork(filepath.Join(root, filepath.FromSlash(head.Signature.Name)))
	bundle, _ := mapSignerWork(filepath.Join(root, "operational", "evidence-bundle.json"))
	bundleSig, _ := mapSignerWork(filepath.Join(root, "operational", "evidence-bundle.sig"))
	out, err := mapSignerWork(releaseDir)
	if err != nil {
		return nil, err
	}
	coordinatorKey, err := pathWithin(signer.Trust, filepath.Join(signer.Trust, "coordinator-public-key.hex"), "/trust")
	if err != nil {
		return nil, err
	}
	return []string{"mpc-ceremony", "release", "sign", "--ceremony", ceremony, "--ceremony-signature", ceremonySig, "--coordinator-public-key-file", coordinatorKey, "--review-checkpoint", checkpoint, "--review-checkpoint-signature", checkpointSig, "--operational-evidence-root", artifactRoot, "--operational-bundle", bundle, "--operational-bundle-signature", bundleSig, "--release-signing-key", "/keys/signing.hex", "--signature-key-id", keyID, "--released-at", releasedAt.Format(time.RFC3339Nano), "--release-dir", out}, nil
}

func runWorkflowV4ReleaseUpload(ui *coordinatorWizard, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, online guidedProfile, identity, keyID string, progress workflowV4ReleaseSignerProgress) error {
	// The signing command self-verifies, but a retained package may have been
	// changed between invocations. Re-authenticate all bytes immediately before
	// granting them transport significance.
	if err := runWorkflowV4VerifyReleasePackage(online, progress.PackageDir, keyID); err != nil {
		return fmt.Errorf("verify retained signed release package: %w", err)
	}
	grantPath, err := ui.required("Absolute path to the private release upload grant received from the coordinator or Tessera", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(grantPath) || filepath.Clean(grantPath) != grantPath {
		return errors.New("private release grant path must be absolute and clean")
	}
	grant, err := loadStorageFirstGrant(grantPath)
	if err != nil {
		return err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	if err := storagefirst.ValidateReleaseGrantV4At(snapshot, protocol, identity, grant, destination, time.Now().UTC()); err != nil {
		return err
	}
	inventory, sources, paths, err := workflowV4ReleaseFiles(progress.PackageDir)
	if err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(progress.PackageDir), "temporary")
	if err := os.MkdirAll(temporary, 0o700); err != nil {
		return err
	}
	if err := ui.confirm("Upload this complete signed package to the private inbox; upload alone is not coordinator acceptance or public release", "UPLOAD RELEASE PACKAGE"); err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: grant.CeremonyID, AttemptID: grant.AttemptID, Kind: access.SubmissionKindRelease}
	if err := storagefirst.UploadDelivery(storageFirstGrantClient(grant), scope, inventory, sources, paths, temporary); err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "Signed release package upload completed. Wait for the coordinator to verify it and publish a signed final-release checkpoint.")
	return nil
}

func workflowV4ReleaseFiles(root string) (storagefirst.DeliveryInventory, map[string]state.ContentRef, map[string]string, error) {
	inventory := storagefirst.DeliveryInventory{}
	sources := map[string]state.ContentRef{}
	paths := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("release package cannot contain symbolic links")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("release package contains a non-regular file")
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if strings.HasPrefix(name, "../") || len(inventory) >= 2048 {
			return errors.New("release package inventory is invalid or too large")
		}
		ref, err := workflowV4LocalRef(name, path)
		if err != nil {
			return err
		}
		if ref.Digest.Size <= 0 || ref.Digest.Size > 16<<30 {
			return errors.New("release package file is empty or exceeds 16 GiB")
		}
		inventory[name] = ref.Digest.Size
		sources[name] = state.ContentRef{Name: name, SHA256: ref.Digest.SHA256, Size: ref.Digest.Size}
		paths[name] = path
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(inventory) == 0 {
		return nil, nil, nil, errors.New("release package is empty")
	}
	return inventory, sources, paths, nil
}
