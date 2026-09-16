package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

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
	downloaded, err := storagefirst.FetchDelivery(objects, storagefirst.DeliveryScope{CeremonyID: config.CeremonyID, AttemptID: attempt, Kind: "candidate"}, workflowV4CandidateDeliveryInventory(), filepath.Dir(out))
	if err != nil {
		return err
	}
	if err := os.Rename(downloaded, out); err != nil {
		_ = os.RemoveAll(downloaded)
		return err
	}
	if err := syncDirectory(filepath.Dir(out)); err != nil {
		return err
	}
	fmt.Printf("Downloaded and transport-checked the fixed five-file candidate to %s. It is not accepted; proof-tool must replay it.\n", out)
	return nil
}
