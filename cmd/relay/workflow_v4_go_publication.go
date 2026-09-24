package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// Publication deliberately leaves proof-tool's final-release checkpoint
// unchanged. Its already-signed GO is verified by that same pinned proof-tool;
// the separate coordinator-signed pointer commits one official destination.
func runWorkflowV4PublishGo(ui *coordinatorWizard, online guidedProfile, config access.StorageConfig, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	if online.Role != "coordinator" || !workflowV4CoordinatorDirectRelease(protocol) || config.CeremonyID != protocol.Definition.CeremonyID || config.Provider != "aws" || config.CoordinatorProfile == "" {
		return errors.New("GO publication requires the matching V5 AWS coordinator workspace")
	}
	archive := filepath.Join(online.Work, "workflow-v4", "publication", "go-ceremony.zip")
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("prepare the coordinator's regular GO archive before publication")
	}
	digest, err := workflowV4ArchiveSHA256(archive)
	if err != nil {
		return err
	}
	root, manifest, err := verification.Extract(archive, 1<<40)
	if err != nil {
		return fmt.Errorf("validate complete GO archive inventory: %w", err)
	}
	defer os.RemoveAll(root)
	if manifest.CeremonyID != protocol.Definition.CeremonyID || manifest.Decision == nil || manifest.Inputs["ceremony"] != workflowV4ArchivePrefix+"ceremony.json" || manifest.Inputs["ceremony-signature"] != workflowV4ArchivePrefix+"ceremony.sig" {
		return errors.New("GO archive differs from the authenticated ceremony or lacks its decision")
	}
	decisionFiles, signatures, err := workflowV4DecisionArchiveFiles(filepath.Join(root, "ceremony", "public"))
	if err != nil {
		return err
	}
	expected, err := workflowV4PublicArchiveManifest(snapshot, protocol, decisionFiles, signatures)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected.Inputs, manifest.Inputs) || !reflect.DeepEqual(expected.Decision, manifest.Decision) || expected.ReleaseKeyID != manifest.ReleaseKeyID || len(expected.Files) != len(manifest.Files) {
		return errors.New("GO archive differs from the authenticated final checkpoint")
	}
	bound := make(map[string]verification.File, len(expected.Files))
	for _, file := range expected.Files {
		bound[file.Path] = file
	}
	for _, file := range manifest.Files {
		want, ok := bound[file.Path]
		if !ok || want.SHA256 != workflowV4ZeroSHA256 && (want.SHA256 != file.SHA256 || want.Size != file.Size) {
			return fmt.Errorf("GO archive file differs from signed inventory: %s", file.Path)
		}
	}
	archivedKey, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"])), 4096, false)
	if err != nil {
		return err
	}
	trustedKey, err := readTesseraRegularFile(filepath.Join(online.Trust, "setup-coordinator.hex"), 4096, false)
	if err != nil || !sameCoordinatorPublicKey(archivedKey, trustedKey) {
		return errors.New("GO archive coordinator key differs from the coordinator's trusted key")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(trustedKey)))
	if err != nil {
		return err
	}
	rawPointer, err := readTesseraRegularFile(filepath.Join(online.Work, "workflow-v4", "publication", "go-publication.json"), 16<<20, false)
	if err != nil {
		return err
	}
	record, err := workflowV4VerifyGoPublication(rawPointer, key)
	if err != nil {
		return err
	}
	if record.CeremonyID != manifest.CeremonyID || record.ArchiveSHA256 != digest || record.CheckpointSHA256 != strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:") || record.CheckpointPath != workflowV4ArchivePrefix+snapshot.Head().Record.Name || record.CheckpointSignaturePath != workflowV4ArchivePrefix+snapshot.Head().Signature.Name || record.PublishedBucket != config.PublishedBucket || record.PublishedBaseURL != config.PublishedBaseURL {
		return errors.New("GO authorization differs from authenticated release, archive or storage")
	}
	decisionRaw, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Decision.Record)), 16<<20, false)
	if err != nil {
		return err
	}
	var decision struct {
		Decision   string `json:"decision"`
		CeremonyID string `json:"ceremony_id"`
		Release    struct {
			ReleaseID              string                        `json:"release_id"`
			FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		} `json:"release"`
	}
	if json.Unmarshal(decisionRaw, &decision) != nil || decision.Decision != "GO" || decision.CeremonyID != record.CeremonyID || decision.Release.ReleaseID != record.ReleaseID || workflowV4DigestBytes(decisionRaw) != record.DecisionSHA256 {
		return errors.New("GO authorization differs from the exact signed decision")
	}
	if decision.Release.FinalReleaseCheckpoint != snapshot.Head() {
		return errors.New("signed GO decision approves a different final-release checkpoint")
	}
	if err := workflowV4MatchGoDecisionCheckpoint(root, record, decision.Release.FinalReleaseCheckpoint); err != nil {
		return err
	}
	// The keyless approved image verifies the release and all decision signers.
	proof := online
	proof.Work, proof.Keys, proof.Credentials = root, "", ""
	p := func(name string) string { return "/work/" + name }
	common := []string{"--ceremony", p(manifest.Inputs["ceremony"]), "--ceremony-signature", p(manifest.Inputs["ceremony-signature"]), "--coordinator-public-key-file", "/trust/setup-coordinator.hex"}
	release := append([]string{"mpc-ceremony", "release", "verify"}, common...)
	release = append(release, "--keys-dir", p(manifest.Inputs["keys-dir"]), "--manifest-public-key-file", p(manifest.Inputs["manifest-public-key-file"]), "--signature-key-id", manifest.ReleaseKeyID)
	if err := runWorkflowV4ProfileCommand(proof, release, false); err != nil {
		return fmt.Errorf("verify signed GO release: %w", err)
	}
	verify := append([]string{"mpc-ceremony", "decision", "verify"}, common...)
	verify = append(verify, "--decision", p(manifest.Decision.Record), "--evidence-root", p(manifest.Decision.EvidenceRoot))
	for _, name := range manifest.Decision.Signatures {
		verify = append(verify, "--signature", p(name))
	}
	if err := runWorkflowV4ProfileCommand(proof, verify, false); err != nil {
		return fmt.Errorf("verify exact GO and required signatures: %w", err)
	}
	objects := store.Client{Profile: config.CoordinatorProfile, Region: config.Region, Endpoint: config.Endpoint, Bucket: config.PublishedBucket}
	public := store.Client{PublicBaseURL: config.PublishedBaseURL}
	if err := ui.confirm("Publish only the exact signed GO archive and the one fixed approved-release pointer", "PUBLISH APPROVED GO"); err != nil {
		return err
	}
	// The archive may require multipart upload. Completion is conditional;
	// uncertain results are accepted only after full public SHA-256 readback.
	putErr := objects.PutLargeNoReplace(record.ArchiveKey, archive, online.Work)
	if err := workflowV4GoArchiveReadback(public, record.ArchiveKey, archive, digest, online.Work); err != nil {
		return fmt.Errorf("GO archive upload/readback uncertain (upload: %v): %w", putErr, err)
	}
	if putErr != nil && !errors.Is(putErr, store.ErrExists) {
		// A lost success response is reconciled by the exact full readback above.
		fmt.Fprintf(ui.output, "Archive upload response was uncertain; exact public readback matched: %v\n", putErr)
	}
	pointerFile, err := os.CreateTemp(online.Work, ".go-pointer-*")
	if err != nil {
		return err
	}
	defer os.Remove(pointerFile.Name())
	if _, err := pointerFile.Write(rawPointer); err != nil {
		pointerFile.Close()
		return err
	}
	if err := pointerFile.Close(); err != nil {
		return err
	}
	if err := objects.PutNoReplace(record.PointerKey, pointerFile.Name()); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("approved pointer upload uncertain: %w", err)
	}
	if err := workflowV4GoPointerReadback(public, record.PointerKey, rawPointer, online.Work); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Published exact GO archive and approved pointer: %s/%s\nRun the coordinator's independent official readback action next.\n", strings.TrimSuffix(record.PublishedBaseURL, "/"), record.PointerKey)
	return nil
}

func workflowV4GoPointerReadback(public store.Client, key string, expected []byte, work string) error {
	dir, err := os.MkdirTemp(work, ".go-pointer-readback-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "release.json")
	var readErr error
	for attempt := 0; attempt < 5; attempt++ {
		if readErr = public.GetPublicAtMost(key, path, 16<<20); readErr == nil {
			break
		}
		if attempt < 4 {
			time.Sleep(2 * time.Second)
		}
	}
	if readErr != nil {
		return fmt.Errorf("read approved pointer: %w", readErr)
	}
	actual, err := readTesseraRegularFile(path, 16<<20, false)
	if err != nil || string(actual) != string(expected) {
		return errors.New("official pointer differs from the exact signed GO authorization")
	}
	return nil
}

func workflowV4GoArchiveReadback(public store.Client, key, archive, digest, work string) error {
	info, err := os.Stat(archive)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<40 {
		return errors.New("invalid local GO archive size")
	}
	dir, err := os.MkdirTemp(work, ".go-archive-readback-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ceremony.zip")
	var readErr error
	for attempt := 0; attempt < 5; attempt++ {
		if readErr = public.GetPublicAtMost(key, path, info.Size()); readErr == nil {
			break
		}
		if attempt < 4 {
			time.Sleep(2 * time.Second)
		}
	}
	if readErr != nil {
		return fmt.Errorf("read approved archive: %w", readErr)
	}
	actual, err := workflowV4ArchiveSHA256(path)
	if err != nil || actual != digest {
		return errors.New("published GO archive differs from the exact signed archive")
	}
	return nil
}

func runWorkflowV4CoordinatorGoReadback(ui *coordinatorWizard, online guidedProfile, driver dockerDriver, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	if online.Role != "coordinator" || protocol.DefinitionSchema != "proof-tool-mpc-ceremony-definition-v5" || protocol.Definition.Mode != "production" {
		return errors.New("GO publication readback requires the production coordinator")
	}
	config, err := loadStorageConfig(filepath.Join(online.Work, "ceremony", "config", "relay-storage.json"))
	if err != nil || config.CeremonyID != protocol.Definition.CeremonyID {
		return errors.New("matching coordinator public storage settings required")
	}
	archive := filepath.Join(online.Work, "workflow-v4", "publication", "go-ceremony.zip")
	root, manifest, err := verification.Extract(archive, 1<<40)
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	archivedKey, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"])), 4096, false)
	if err != nil {
		return err
	}
	trustedKey, err := readTesseraRegularFile(filepath.Join(online.Trust, "setup-coordinator.hex"), 4096, false)
	if err != nil || !sameCoordinatorPublicKey(archivedKey, trustedKey) {
		return errors.New("published GO archive differs from the coordinator's trusted key")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(trustedKey)))
	if err != nil {
		return err
	}
	pointerRaw, err := readTesseraRegularFile(filepath.Join(online.Work, "workflow-v4", "publication", "go-publication.json"), 16<<20, false)
	if err != nil {
		return err
	}
	record, err := workflowV4VerifyGoPublication(pointerRaw, key)
	if err != nil {
		return err
	}
	if record.CeremonyID != protocol.Definition.CeremonyID || record.CheckpointSHA256 != strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:") || record.CheckpointPath != workflowV4ArchivePrefix+snapshot.Head().Record.Name || record.CheckpointSignaturePath != workflowV4ArchivePrefix+snapshot.Head().Signature.Name || record.PublishedBucket != config.PublishedBucket || record.PublishedBaseURL != config.PublishedBaseURL {
		return errors.New("published GO differs from the coordinator's authenticated final checkpoint or destination")
	}
	verifier := workflowV4GoVerifierDriver(driver, root, manifest)
	run := func(args ...string) ([]byte, error) {
		out, stderr, err := verifier.inspectionRunner(dockerCeremonyBinary, append([]string{"--format", "json"}, args...)...)
		if err != nil {
			return nil, fmt.Errorf("pinned Docker proof verifier: %w: %s", err, strings.TrimSpace(string(stderr)))
		}
		return out, nil
	}
	report, err := verifyExtractedCeremonyArchiveWithPublicationTrusted(root, manifest, archive, run, config.PublishedBaseURL, protocol.Definition.CeremonyID, trustedKey)
	if err != nil || !report.Passed {
		return fmt.Errorf("independent published GO verification failed: %w", err)
	}
	fmt.Fprintf(ui.output, "The official GO pointer and independently downloaded archive match the reviewed local archive at %s.\n", config.PublishedBaseURL)
	return nil
}

func workflowV4GoVerifierDriver(driver dockerDriver, root string, manifest verification.Manifest) dockerDriver {
	driver.root = root
	driver.inspectionRoot = root
	driver.definition = filepath.Join(root, filepath.FromSlash(manifest.Inputs["ceremony"]))
	driver.definitionSig = filepath.Join(root, filepath.FromSlash(manifest.Inputs["ceremony-signature"]))
	driver.coordinatorKey = filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"]))
	return driver
}
