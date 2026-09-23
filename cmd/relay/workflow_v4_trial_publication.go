package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/verification"
)

// This public trial lane deliberately has no approved-release pointer. GO
// promotion still requires the terminal decision and publication checkpoints
// specified by the protocol design.
func runWorkflowV4PublishNoGoTrial(ui *coordinatorWizard, online guidedProfile, config access.StorageConfig, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	if online.Role != "upload-station" || protocol.Definition.Mode != "production" || protocol.DefinitionSchema != "proof-tool-mpc-ceremony-definition-v5" || config.CeremonyID != protocol.Definition.CeremonyID {
		return errors.New("NO-GO trial publication requires the exact authenticated V5 upload-station workspace")
	}
	if config.Provider != "aws" || config.CoordinatorProfile == "" || config.PublishedBucket == "" {
		return errors.New("this trial publication lane requires configured AWS test-bucket access")
	}
	archive := filepath.Join(online.Work, "no-go-trial-ceremony.zip")
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("place the coordinator's regular public trial ZIP in this upload workspace first")
	}
	digest, err := workflowV4ArchiveSHA256(archive)
	if err != nil {
		return err
	}
	root, manifest, err := verification.Extract(archive, 1<<40)
	if err != nil {
		return fmt.Errorf("validate complete trial archive inventory: %w", err)
	}
	defer os.RemoveAll(root)
	if manifest.CeremonyID != protocol.Definition.CeremonyID || manifest.Decision == nil || manifest.Inputs["ceremony"] != workflowV4ArchivePrefix+"ceremony.json" || manifest.Inputs["ceremony-signature"] != workflowV4ArchivePrefix+"ceremony.sig" {
		return errors.New("trial archive does not match the signed ceremony or lacks its production decision")
	}
	decisionFiles, signatures, err := workflowV4DecisionArchiveFiles(filepath.Join(root, "ceremony", "public"))
	if err != nil {
		return err
	}
	expected, err := workflowV4PublicArchiveManifest(snapshot, protocol, decisionFiles, signatures)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected.Inputs, manifest.Inputs) || !reflect.DeepEqual(expected.Decision, manifest.Decision) || expected.ReleaseKeyID != manifest.ReleaseKeyID {
		return errors.New("trial archive inputs differ from the authenticated final checkpoint and decision handoff")
	}
	expectedFiles := make(map[string]verification.File, len(expected.Files))
	for _, file := range expected.Files {
		expectedFiles[file.Path] = file
	}
	if len(manifest.Files) != len(expectedFiles) {
		return errors.New("trial archive has missing or extra public files")
	}
	for _, file := range manifest.Files {
		bound, ok := expectedFiles[file.Path]
		if !ok || bound.SHA256 != workflowV4ZeroSHA256 && (bound.SHA256 != file.SHA256 || bound.Size != file.Size) {
			return fmt.Errorf("trial archive file differs from signed inventory: %s", file.Path)
		}
	}
	archivedKey, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"])), 4096, false)
	if err != nil {
		return err
	}
	trustedKey, err := readTesseraRegularFile(filepath.Join(online.Trust, "coordinator-public-key.hex"), 4096, false)
	if err != nil {
		return err
	}
	if !bytes.Equal(archivedKey, trustedKey) {
		return errors.New("archive coordinator key differs from the independently trusted key")
	}
	// Verify the complete signed release and decision in the approved image.
	// The archive extractor has already checked every listed byte and rejected
	// extra ZIP entries; no private key or cloud credential is mounted here.
	proof := online
	proof.Work = root
	proof.Keys = ""
	proof.Credentials = ""
	path := func(name string) string { return "/work/" + name }
	common := []string{"--ceremony", path(manifest.Inputs["ceremony"]), "--ceremony-signature", path(manifest.Inputs["ceremony-signature"]), "--coordinator-public-key-file", "/trust/coordinator-public-key.hex"}
	release := append([]string{"mpc-ceremony", "release", "verify"}, common...)
	release = append(release, "--keys-dir", path(manifest.Inputs["keys-dir"]), "--manifest-public-key-file", path(manifest.Inputs["manifest-public-key-file"]), "--signature-key-id", manifest.ReleaseKeyID)
	if err := runWorkflowV4ProfileCommand(proof, release, false); err != nil {
		return fmt.Errorf("verify exact archived signed release: %w", err)
	}
	decision := append([]string{"mpc-ceremony", "decision", "verify"}, common...)
	decision = append(decision, "--decision", path(manifest.Decision.Record), "--evidence-root", path(manifest.Decision.EvidenceRoot))
	for _, name := range manifest.Decision.Signatures {
		decision = append(decision, "--signature", path(name))
	}
	if err := runWorkflowV4ProfileCommand(proof, decision, false); err != nil {
		return fmt.Errorf("verify exact archived decision and signatures: %w", err)
	}
	raw, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Decision.Record)), 16<<20, false)
	if err != nil {
		return err
	}
	var outcome struct {
		Decision   string `json:"decision"`
		CeremonyID string `json:"ceremony_id"`
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return err
	}
	if outcome.Decision != "NO-GO" || outcome.CeremonyID != manifest.CeremonyID {
		return errors.New("this public trial lane requires an exact verified NO-GO for the same ceremony")
	}
	ceremonyHex := strings.TrimPrefix(manifest.CeremonyID, "sha256:")
	key := "trials/no-go/" + ceremonyHex + "/" + digest + "/ceremony.zip"
	objects := store.Client{Profile: config.CoordinatorProfile, Region: config.Region, Endpoint: config.Endpoint, Bucket: config.PublishedBucket}
	public := store.Client{PublicBaseURL: config.PublishedBaseURL}
	if err := ui.confirm("Publish this verified NO-GO archive under a content-addressed trial prefix; this never creates an approved-release pointer", "PUBLISH NO-GO TRIAL"); err != nil {
		return err
	}
	if err := publishWorkflowV4LargeTrialArchive(objects, public, config, key, archive, digest, online.Work); err != nil {
		return err
	}
	notice := []byte("NO-GO TRIAL ARCHIVE\nCeremony: " + manifest.CeremonyID + "\nArchive SHA-256: " + digest + "\nThis archive is public test evidence. The signed decision inside is NO-GO; these keys are not approved for production use. Read its evidence for operator and host limitations.\n")
	if err := publishWorkflowV4TrialNotice(objects, public, strings.TrimSuffix(key, "ceremony.zip")+"README.txt", notice, online.Work); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Published and read back exact NO-GO trial archive: %s/%s\nSHA-256: %s\nNo production approval or approved-release pointer was created.\n", strings.TrimSuffix(config.PublishedBaseURL, "/"), key, digest)
	return nil
}

func publishWorkflowV4TrialNotice(objects, public store.Client, key string, notice []byte, work string) error {
	if !strings.HasPrefix(key, "trials/no-go/") || !strings.HasSuffix(key, "/README.txt") {
		return errors.New("invalid NO-GO trial notice key")
	}
	f, err := os.CreateTemp(work, ".trial-notice-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(notice); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := objects.PutNoReplace(key, name); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("trial notice upload uncertain; inspect the object before retrying: %w", err)
	}
	readback, err := os.CreateTemp(work, ".trial-notice-readback-*")
	if err != nil {
		return err
	}
	readbackName := readback.Name()
	readback.Close()
	defer os.Remove(readbackName)
	if err := public.Get(key, readbackName); err != nil {
		return err
	}
	actual, err := readTesseraRegularFile(readbackName, 4096, false)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, notice) {
		return errors.New("published trial notice differs from the reviewed NO-GO label")
	}
	return nil
}

func publishWorkflowV4LargeTrialArchive(objects, public store.Client, config access.StorageConfig, key, archive, digest, work string) error {
	if !strings.HasPrefix(key, "trials/no-go/") || !strings.HasSuffix(key, "/"+digest+"/ceremony.zip") {
		return errors.New("invalid content-addressed NO-GO trial object key")
	}
	present, err := objects.Head(key)
	if err != nil {
		return err
	}
	if !present {
		// Archives can exceed S3's single PutObject size. The AWS CLI handles
		// multipart upload; the SHA-addressed key and exact public readback make
		// an interrupted retry detectable without a blind success claim.
		cmd := exec.Command("aws", "--profile", config.CoordinatorProfile, "--region", config.Region, "s3", "cp", archive, "s3://"+config.PublishedBucket+"/"+key, "--no-progress")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			// The client may have lost the success response. Read back before
			// treating the operation as failed or attempting another upload.
			if checkErr := checkWorkflowV4TrialReadback(public, key, digest, work); checkErr == nil {
				return nil
			}
			return fmt.Errorf("trial archive upload uncertain; inspect the object before retrying: %w", err)
		}
	}
	return checkWorkflowV4TrialReadback(public, key, digest, work)
}

func checkWorkflowV4TrialReadback(public store.Client, key, digest, work string) error {
	f, err := os.CreateTemp(work, ".trial-readback-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	defer os.Remove(name)
	var downloadErr error
	for attempt := 0; attempt < 5; attempt++ {
		if downloadErr = public.Get(key, name); downloadErr == nil {
			break
		}
		if attempt < 4 {
			time.Sleep(2 * time.Second)
		}
	}
	if downloadErr != nil {
		return fmt.Errorf("download published trial archive: %w", downloadErr)
	}
	actual, err := workflowV4ArchiveSHA256(name)
	if err != nil {
		return err
	}
	if actual != digest {
		return errors.New("published trial archive bytes differ from the verified local archive")
	}
	return nil
}
