package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

const workflowV4CandidateFetchReceiptSchema = "relay-workflow-v4-candidate-fetch-v1"

// workflowV4CandidateFetchReceipt remains beside, never inside, the fixed
// protocol candidate directory. The proof-tool rejection command requires
// that directory to contain exactly its five protocol files.
type workflowV4CandidateFetchReceipt struct {
	Schema     string             `json:"schema"`
	CeremonyID string             `json:"ceremony_id"`
	AttemptID  string             `json:"attempt_id"`
	Kind       string             `json:"kind"`
	Manifest   state.ContentRef   `json:"manifest"`
	Files      []state.ContentRef `json:"files"`
}

// runCoordinatorFetchCandidateV4 downloads one allocated transport attempt
// through coordinator-authenticated inbox access. It does not accept the
// candidate; proof-tool later replays and verifies it in the signing container.
func runCoordinatorFetchCandidateV4(args []string) error {
	set := flag.NewFlagSet("coordinator fetch-candidate-v4", flag.ContinueOnError)
	var storagePath, root, checkpoint, signature, attempt, out, ceremony, ceremonySignature, coordinatorKey, ceremonyBinary string
	set.StringVar(&storagePath, "storage", "", "verified public storage configuration")
	set.StringVar(&root, "artifact-root", "", "complete retained public artifact root")
	set.StringVar(&checkpoint, "checkpoint", "", "current signed checkpoint")
	set.StringVar(&signature, "checkpoint-signature", "", "current detached checkpoint signature")
	set.StringVar(&attempt, "attempt-id", "", "active candidate attempt")
	set.StringVar(&out, "out-dir", "", "fresh private candidate directory")
	set.StringVar(&ceremony, "ceremony", "", "signed ceremony definition")
	set.StringVar(&ceremonySignature, "ceremony-signature", "", "definition signature")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "independently authenticated coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "approved proof-tool executable")
	if err := set.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"--storage": storagePath, "--artifact-root": root, "--checkpoint": checkpoint, "--checkpoint-signature": signature, "--out-dir": out, "--ceremony": ceremony, "--ceremony-signature": ceremonySignature, "--coordinator-key": coordinatorKey} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s requires an absolute clean path", name)
		}
	}
	if attempt == "" {
		return errors.New("--attempt-id is required")
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	if config.CeremonyPath != ceremony || config.CeremonySignature != ceremonySignature || config.CoordinatorPublicKey != coordinatorKey {
		return errors.New("storage configuration and exact authenticated ceremony paths differ")
	}
	if _, err := publicationNameV4(root, checkpoint); err != nil {
		return fmt.Errorf("checkpoint path: %w", err)
	}
	if _, err := publicationNameV4(root, signature); err != nil {
		return fmt.Errorf("checkpoint signature path: %w", err)
	}
	inspector := transcript.Inspector{Executable: ceremonyBinary, CeremonyPath: ceremony, CeremonySignaturePath: ceremonySignature, CoordinatorPublicKeyPath: coordinatorKey, TranscriptRoot: root}
	inspection, err := inspector.StoredCheckpointV4(root, checkpoint, signature)
	if err != nil {
		return err
	}
	if inspection.Checkpoint.CeremonyID != config.CeremonyID {
		return errors.New("checkpoint and storage configuration belong to different ceremonies")
	}
	active := false
	for _, slot := range inspection.Checkpoint.Deliveries {
		if slot.AttemptID == attempt && slot.Kind == "candidate" && slot.Status == "allocated" {
			active = true
		}
	}
	if !active {
		return errors.New("attempt is not an active candidate allocation in the authenticated checkpoint")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return errors.New("candidate output already exists; inspect and verify it instead of downloading over it")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	objects := coordinatorClient(config, config.InboxBucket)
	fetched, err := storagefirst.FetchDeliveryVerified(objects, storagefirst.DeliveryScope{CeremonyID: config.CeremonyID, AttemptID: attempt, Kind: "candidate"}, workflowV4CandidateDeliveryInventory(), filepath.Dir(out))
	if err != nil {
		return err
	}
	if err := os.Rename(fetched.Dir, out); err != nil {
		_ = os.RemoveAll(fetched.Dir)
		return err
	}
	if err := syncDirectory(filepath.Dir(out)); err != nil {
		return err
	}
	receipt := workflowV4CandidateFetchReceipt{Schema: workflowV4CandidateFetchReceiptSchema, CeremonyID: config.CeremonyID, AttemptID: attempt, Kind: "candidate", Manifest: fetched.Manifest, Files: fetched.Files}
	if err := writeJSONNoReplace(workflowV4CandidateFetchReceiptPath(out), receipt, 0o600); err != nil {
		return fmt.Errorf("record transport-checked candidate receipt: %w", err)
	}
	fmt.Printf("Downloaded and transport-checked the fixed five-file candidate to %s. It is not accepted; proof-tool must replay it.\n", out)
	return nil
}

func workflowV4CandidateFetchReceiptPath(candidateDir string) string {
	return candidateDir + ".fetch.json"
}

// quarantineWorkflowV4CandidateDownload preserves an incomplete or changed
// local download before a fresh fetch. It creates a new retained directory and
// syncs both sides of each move, so it never overwrites prior local evidence.
// The new fetch still has to pass the same authenticated manifest and fixed
// five-file payload checks.
func quarantineWorkflowV4CandidateDownload(candidateDir string) (string, error) {
	parent := filepath.Dir(candidateDir)
	retainedRoot := filepath.Join(parent, "retained")
	if err := os.MkdirAll(retainedRoot, 0o700); err != nil {
		return "", err
	}
	if err := syncDirectory(parent); err != nil {
		return "", err
	}
	retained, err := os.MkdirTemp(retainedRoot, filepath.Base(candidateDir)+"-")
	if err != nil {
		return "", err
	}
	if err := syncDirectory(retainedRoot); err != nil {
		return "", err
	}
	move := func(source, destination string) error {
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return errors.New("retained recovery destination already exists")
			}
			return err
		}
		if err := os.Rename(source, destination); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(source)); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(destination))
	}
	receipt := workflowV4CandidateFetchReceiptPath(candidateDir)
	if _, err := os.Lstat(receipt); err == nil {
		if err := move(receipt, filepath.Join(retained, "transport-receipt.json")); err != nil {
			return "", fmt.Errorf("preserve candidate transport receipt: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := move(candidateDir, filepath.Join(retained, "candidate")); err != nil {
		return "", fmt.Errorf("preserve candidate download: %w", err)
	}
	return retained, nil
}

// validateWorkflowV4CandidateFetchReceipt proves that the retained directory
// is still the exact five-file package previously returned by FetchDelivery.
// It does not authenticate the contribution: proof-tool does that separately.
func validateWorkflowV4CandidateFetchReceipt(candidateDir string, scope transcript.ContributionScopeV4, attempt string) error {
	var receipt workflowV4CandidateFetchReceipt
	if err := readWorkflowV4JSON(workflowV4CandidateFetchReceiptPath(candidateDir), &receipt); err != nil {
		return fmt.Errorf("read candidate transport receipt: %w", err)
	}
	if receipt.Schema != workflowV4CandidateFetchReceiptSchema || receipt.CeremonyID != scope.CeremonyID || receipt.AttemptID != attempt || receipt.Kind != "candidate" || receipt.Manifest.Name != "manifest.json" || !validCoordinatorCommitDigest(receipt.Manifest.SHA256) || receipt.Manifest.Size <= 0 {
		return errors.New("candidate transport receipt does not match the active signed allocation")
	}
	expected := workflowV4CandidateDeliveryInventory()
	if len(receipt.Files) != len(expected) {
		return errors.New("candidate transport receipt has an unexpected file set")
	}
	refs := make(map[string]state.ContentRef, len(receipt.Files))
	for _, ref := range receipt.Files {
		if ref.Name == "" || ref.Size <= 0 || ref.Size > expected[ref.Name] || !validCoordinatorCommitDigest(ref.SHA256) {
			return errors.New("candidate transport receipt has an invalid file reference")
		}
		if _, duplicate := refs[ref.Name]; duplicate {
			return errors.New("candidate transport receipt repeats a file")
		}
		refs[ref.Name] = ref
	}
	entries, err := os.ReadDir(candidateDir)
	if err != nil {
		return err
	}
	if len(entries) != len(expected) {
		return errors.New("retained candidate directory has an unexpected file set")
	}
	for name := range expected {
		ref, ok := refs[name]
		if !ok {
			return errors.New("candidate transport receipt omits a required file")
		}
		if err := verifyWorkflowV4CandidateReceiptFile(filepath.Join(candidateDir, name), ref); err != nil {
			return fmt.Errorf("revalidate transport-checked candidate %s: %w", name, err)
		}
	}
	return nil
}

func verifyWorkflowV4CandidateReceiptFile(path string, ref state.ContentRef) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != ref.Size {
		return errors.New("candidate file is not the expected regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return errors.New("candidate file changed while opening")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, before.Size()+1))
	if err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || "sha256:"+fmt.Sprintf("%x", hash.Sum(nil)) != ref.SHA256 {
		return errors.New("candidate file changed while hashing")
	}
	return nil
}
