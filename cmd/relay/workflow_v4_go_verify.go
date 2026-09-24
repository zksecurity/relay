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
	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/verification"
)

// The caller supplies the independently trusted official URL. A URL embedded
// in the archive cannot declare itself official.
func workflowV4VerifyPublishedGo(root string, manifest verification.Manifest, archive, baseURL string, run publicVerifyRunner) error {
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
			ReleaseID              string                        `json:"release_id"`
			FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		} `json:"release"`
	}
	if json.Unmarshal(decisionRaw, &decision) != nil || decision.Decision != "GO" || record.DecisionSHA256 != workflowV4DigestBytes(decisionRaw) || record.ReleaseID != decision.Release.ReleaseID {
		return errors.New("official GO pointer differs from the verified signed decision")
	}
	if err := workflowV4MatchGoDecisionCheckpoint(root, record, decision.Release.FinalReleaseCheckpoint); err != nil {
		return err
	}
	checkpointRaw, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(record.CheckpointPath)), 16<<20, false)
	if err != nil || workflowV4DigestBytes(checkpointRaw) != record.CheckpointSHA256 {
		return errors.New("official GO pointer names a checkpoint absent from the archive")
	}
	if _, err := readTesseraRegularFile(filepath.Join(root, filepath.FromSlash(record.CheckpointSignaturePath)), 4096, false); err != nil {
		return fmt.Errorf("official GO checkpoint signature: %w", err)
	}
	if !workflowV4ManifestHasFile(manifest, record.CheckpointPath, record.CheckpointSHA256) || !workflowV4ManifestHasFile(manifest, record.CheckpointSignaturePath, "") {
		return errors.New("official GO checkpoint pair is absent from the closed archive inventory")
	}
	if run == nil {
		return errors.New("pinned checkpoint verifier required for official GO")
	}
	args := []string{"checkpoint", "verify-stored-v4", "--ceremony", filepath.Join(root, filepath.FromSlash(manifest.Inputs["ceremony"])), "--ceremony-signature", filepath.Join(root, filepath.FromSlash(manifest.Inputs["ceremony-signature"])), "--coordinator-public-key-file", filepath.Join(root, filepath.FromSlash(manifest.Inputs["coordinator-public-key-file"])), "--artifact-root", filepath.Join(root, "ceremony", "public"), "--checkpoint", filepath.Join(root, filepath.FromSlash(record.CheckpointPath)), "--checkpoint-signature", filepath.Join(root, filepath.FromSlash(record.CheckpointSignaturePath))}
	verifiedRaw, err := run(args...)
	if err != nil {
		return fmt.Errorf("authenticate official GO final checkpoint: %w", err)
	}
	var verified struct {
		Schema               string `json:"schema"`
		OK                   bool   `json:"ok"`
		Command              string `json:"command"`
		CeremonyID           string `json:"ceremony_id"`
		CheckpointInspection struct {
			Schema     string `json:"schema"`
			Depth      string `json:"depth"`
			Checkpoint struct {
				Transition struct {
					Kind string `json:"kind"`
				} `json:"transition"`
				Progress struct {
					FinalRelease json.RawMessage `json:"final_release"`
				} `json:"progress"`
			} `json:"checkpoint"`
		} `json:"checkpoint_inspection_v4"`
	}
	if json.Unmarshal(verifiedRaw, &verified) != nil || verified.Schema != "proof-tool-mpc-command-result-v1" || !verified.OK || verified.Command != "checkpoint verify-stored-v4" || verified.CeremonyID != manifest.CeremonyID || verified.CheckpointInspection.Schema != "proof-tool-mpc-checkpoint-inspection-v4" || verified.CheckpointInspection.Depth != "checkpoint-structure" || verified.CheckpointInspection.Checkpoint.Transition.Kind != "final-release-recorded" || len(verified.CheckpointInspection.Checkpoint.Progress.FinalRelease) == 0 || string(verified.CheckpointInspection.Checkpoint.Progress.FinalRelease) == "null" {
		return errors.New("official GO pointer does not name an authenticated final-release checkpoint")
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

func workflowV4MatchGoDecisionCheckpoint(root string, record workflowV4GoPublication, head transcript.SignedArtifactRefs) error {
	if record.CheckpointPath != workflowV4ArchivePrefix+head.Record.Name || record.CheckpointSignaturePath != workflowV4ArchivePrefix+head.Signature.Name || head.Record.Digest.SHA256 != "sha256:"+record.CheckpointSHA256 {
		return errors.New("official GO checkpoint differs from the exact checkpoint approved by the signed decision")
	}
	for _, ref := range []transcript.ArtifactRef{head.Record, head.Signature} {
		if !strings.HasPrefix(ref.Digest.SHA256, "sha256:") || ref.Digest.Size <= 0 {
			return errors.New("signed GO decision has an invalid final checkpoint reference")
		}
		path := filepath.Join(root, filepath.FromSlash(workflowV4ArchivePrefix+ref.Name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != ref.Digest.Size {
			return errors.New("signed GO decision checkpoint size differs from archive")
		}
		raw, err := readTesseraRegularFile(path, 16<<20, false)
		if err != nil || workflowV4DigestBytes(raw) != strings.TrimPrefix(ref.Digest.SHA256, "sha256:") {
			return errors.New("signed GO decision checkpoint digest differs from archive")
		}
	}
	return nil
}

func workflowV4ManifestHasFile(manifest verification.Manifest, path, digest string) bool {
	for _, file := range manifest.Files {
		if file.Path == path && (digest == "" || file.SHA256 == digest) {
			return true
		}
	}
	return false
}
