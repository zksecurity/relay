package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/verification"
)

// The caller supplies the independently trusted official URL. A URL embedded
// in the archive cannot declare itself official.
func workflowV4VerifyPublishedGo(root string, manifest verification.Manifest, archive, baseURL string) error {
	if err := validateStorageFirstOrigin("official public storage URL", baseURL); err != nil {
		return err
	}
	if manifest.Decision == nil {
		return errors.New("official publication requires a signed GO decision")
	}
	keyRaw, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"])), 4096, false)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil {
		return err
	}
	public := store.Client{PublicBaseURL: baseURL}
	dir, err := os.MkdirTemp("", "relay-go-publication-readback-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	pointerKey := workflowV4GoPointerKey(manifest.CeremonyID)
	pointerPath := filepath.Join(dir, "release.json")
	if err := public.GetPublicAtMost(pointerKey, pointerPath, 16<<20); err != nil {
		return fmt.Errorf("official GO pointer is unavailable: %w", err)
	}
	pointerRaw, err := readTesseraRegularFile(pointerPath, 16<<20, false)
	if err != nil {
		return err
	}
	record, err := workflowV4VerifyGoPublication(pointerRaw, key)
	if err != nil {
		return err
	}
	if record.CeremonyID != manifest.CeremonyID || record.PointerKey != pointerKey || record.PublishedBaseURL != baseURL {
		return errors.New("official GO pointer differs from the trusted ceremony or storage location")
	}
	decisionRaw, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(manifest.Decision.Record)), 16<<20, false)
	if err != nil {
		return err
	}
	var decision struct {
		Decision string `json:"decision"`
		Release  struct {
			ReleaseID string `json:"release_id"`
		} `json:"release"`
	}
	if json.Unmarshal(decisionRaw, &decision) != nil || decision.Decision != "GO" || record.DecisionSHA256 != workflowV4DigestBytes(decisionRaw) || record.ReleaseID != decision.Release.ReleaseID {
		return errors.New("official GO pointer differs from the verified signed decision")
	}
	checkpointFound := false
	for _, file := range manifest.Files {
		if strings.HasPrefix(file.Path, workflowV4ArchivePrefix+"checkpoints/") && file.SHA256 == record.CheckpointSHA256 {
			checkpointFound = true
			break
		}
	}
	if !checkpointFound {
		return errors.New("official GO pointer names a checkpoint absent from the signed archive")
	}
	digest, err := workflowV4ArchiveSHA256(archive)
	if err != nil {
		return err
	}
	if digest != record.ArchiveSHA256 {
		return errors.New("official GO pointer names another archive")
	}
	return workflowV4GoArchiveReadback(public, record.ArchiveKey, archive, digest, dir)
}
