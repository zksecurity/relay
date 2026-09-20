package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

// runCoordinatorCommitV4 publishes an already signed and fully checked V4
// checkpoint. It is intended to run in the coordinator's online role image:
// proof-tool is pinned there and the coordinator storage credential is mounted
// read-only. The two immutable files are uploaded before the mutable root.
func runCoordinatorCommitV4(args []string) error {
	set := flag.NewFlagSet("coordinator commit-v4", flag.ContinueOnError)
	var storagePath, root, checkpoint, signature, ceremony, ceremonySignature, coordinatorKey, ceremonyBinary string
	set.StringVar(&storagePath, "storage", "", "verified public storage configuration")
	set.StringVar(&root, "artifact-root", "", "complete retained public artifact root")
	set.StringVar(&checkpoint, "checkpoint", "", "signed child checkpoint under artifact-root")
	set.StringVar(&signature, "checkpoint-signature", "", "detached child signature under artifact-root")
	set.StringVar(&ceremony, "ceremony", "", "signed ceremony definition")
	set.StringVar(&ceremonySignature, "ceremony-signature", "", "definition signature")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "independently authenticated coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "approved proof-tool executable")
	if err := set.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"--storage": storagePath, "--artifact-root": root, "--checkpoint": checkpoint,
		"--checkpoint-signature": signature, "--ceremony": ceremony,
		"--ceremony-signature": ceremonySignature, "--coordinator-key": coordinatorKey,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s requires an absolute clean path", name)
		}
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	if config.CeremonyPath != ceremony || config.CeremonySignature != ceremonySignature || config.CoordinatorPublicKey != coordinatorKey {
		return errors.New("storage configuration and exact authenticated ceremony paths differ")
	}
	checkpointName, err := publicationNameV4(root, checkpoint)
	if err != nil {
		return fmt.Errorf("checkpoint path: %w", err)
	}
	signatureName, err := publicationNameV4(root, signature)
	if err != nil {
		return fmt.Errorf("checkpoint signature path: %w", err)
	}
	checkpointProjection, err := workflowV4LocalRef(checkpointName, checkpoint)
	if err != nil {
		return err
	}
	signatureProjection, err := workflowV4LocalRef(signatureName, signature)
	if err != nil {
		return err
	}
	checkpointRef := state.ContentRef{Name: checkpointName, SHA256: checkpointProjection.Digest.SHA256, Size: checkpointProjection.Digest.Size}
	signatureRef := state.ContentRef{Name: signatureName, SHA256: signatureProjection.Digest.SHA256, Size: signatureProjection.Digest.Size}
	inspector := transcript.Inspector{Executable: ceremonyBinary, CeremonyPath: ceremony, CeremonySignaturePath: ceremonySignature, CoordinatorPublicKeyPath: coordinatorKey, TranscriptRoot: root}
	child, err := storagefirst.AuthenticateRootChildV4(inspector, checkpointRef, signatureRef, root, checkpoint, signature)
	if err != nil {
		return err
	}
	objects := coordinatorClient(config, config.PublishedBucket)
	// The verified-objects memo is workspace-private state beside the public
	// artifact root: it records which stored versions this coordinator already
	// digest-verified, so the cumulative artifact inventory carried by every
	// checkpoint is confirmed by a metadata request instead of re-downloading
	// each earlier artifact on every commit.
	memo := storagefirst.LoadVerifiedObjects(filepath.Join(filepath.Dir(root), "verified-objects.json"))
	if err := storagefirst.PublishArtifacts(objects, child.PublicationArtifacts(), root, filepath.Dir(root), memo, storagefirst.DefaultPublishLimits()); err != nil {
		return err
	}
	if err := storagefirst.PublishImmutable(objects, checkpointRef, checkpoint, filepath.Dir(root), memo); err != nil {
		return fmt.Errorf("publish immutable checkpoint: %w", err)
	}
	if err := storagefirst.PublishImmutable(objects, signatureRef, signature, filepath.Dir(root), memo); err != nil {
		return fmt.Errorf("publish immutable checkpoint signature: %w", err)
	}
	if err := memo.Save(); err != nil {
		return fmt.Errorf("record verified objects: %w", err)
	}

	// Reread through authenticated provider access. A repeated command after a
	// lost success response is complete only when the exact child is current.
	temp, err := os.MkdirTemp(filepath.Dir(root), "relay-v4-root-read-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	rootPath := filepath.Join(temp, "root.json")
	commit := storagefirst.RootCommit{CeremonyID: config.CeremonyID, Child: child}
	present, err := objects.Head(state.RootKey(config.CeremonyID))
	if err != nil {
		return err
	}
	if present {
		version, err := objects.GetVersionedAtMost(state.RootKey(config.CeremonyID), rootPath, 1<<20)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(rootPath)
		if err != nil {
			return err
		}
		current, err := state.DecodeRoot(raw)
		if err != nil {
			return err
		}
		if current.CeremonyID != config.CeremonyID {
			return errors.New("authenticated storage root belongs to another ceremony")
		}
		if current.Checkpoint == checkpointRef && current.CheckpointSignature == signatureRef {
			fmt.Printf("V4 checkpoint was already the exact authenticated storage head: %s\n", checkpointRef.SHA256)
			return nil
		}
		commit.Previous, commit.PreviousVersion = &current, &version
	}
	committed, err := storagefirst.CommitRoot(objects, commit, filepath.Dir(root))
	if err != nil {
		return err
	}
	fmt.Printf("Published the exact signed V4 checkpoint as the storage head: %s (ETag %s)\n", checkpointRef.SHA256, committed.ETag)
	return nil
}

func publicationNameV4(root, file string) (string, error) {
	relative, err := filepath.Rel(root, file)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("file must be contained by artifact-root")
	}
	name := filepath.ToSlash(relative)
	if err := transcript.ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}
