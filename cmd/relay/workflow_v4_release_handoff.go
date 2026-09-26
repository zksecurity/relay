package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func workflowV4ReleaseHandoffSetupAvailable(work string) bool {
	raw, err := readTesseraRegularFile(filepath.Join(work, "ceremony", "public", "ceremony.json"), 16<<20, false)
	if err != nil {
		return false
	}
	var hint struct {
		Schema string `json:"schema"`
		Mode   string `json:"mode"`
	}
	return json.Unmarshal(raw, &hint) == nil && hint.Schema == "proof-tool-mpc-ceremony-definition-v5" && hint.Mode == "production"
}

func workflowV4WithSignerTransferLock(work string, action func() error) error {
	lock, err := acquireParticipantRunLock("", work)
	if err != nil {
		return fmt.Errorf("save and exit the offline signer guide before using an online transfer: %w", err)
	}
	defer lock.release()
	return action()
}

// A release-review snapshot is public transport, not a verification result.
// The offline guide authenticates its signed history with the separately
// trusted coordinator key after the online, keyless download is complete.
func workflowV4ValidateReleaseSnapshot(m workflowV4PublicSnapshot, ceremonyID, checkpointSHA string) error {
	if m.Schema != "relay-public-snapshot-v1" || m.Root.CeremonyID != ceremonyID || m.Root.Checkpoint.SHA256 != checkpointSHA {
		return errors.New("release snapshot belongs to a different ceremony or checkpoint")
	}
	if err := m.Root.Validate(); err != nil {
		return err
	}
	if len(m.Files) == 0 || len(m.Files) > 65536 {
		return errors.New("invalid release snapshot file count")
	}
	names := map[string]bool{}
	digests := map[string]int64{}
	var total int64
	for _, ref := range m.Files {
		if _, err := workflowV4HandoffHex(ref.SHA256); err != nil || ref.Size <= 0 || ref.Size > 16<<30 ||
			ref.Name == "" || ref.Name == "." || ref.Name == ".." || strings.HasPrefix(ref.Name, "../") || filepath.IsAbs(ref.Name) ||
			filepath.ToSlash(filepath.Clean(ref.Name)) != ref.Name || strings.Contains(ref.Name, `\`) || names[ref.Name] {
			return errors.New("invalid release snapshot file reference")
		}
		names[ref.Name] = true
		if prior, exists := digests[ref.SHA256]; exists && prior != ref.Size {
			return errors.New("conflicting release snapshot object size")
		}
		digests[ref.SHA256] = ref.Size
		if total > 64<<30-ref.Size {
			return errors.New("release snapshot exceeds the 64 GiB bound")
		}
		total += ref.Size
	}
	return nil
}

func workflowV4ReleaseSnapshotManifestPath(work string) string {
	return filepath.Join(work, "workflow-v4", "coordinator", "release", "snapshot-manifest.json")
}

func runWorkflowV4PublishReleaseSnapshot(ui *coordinatorWizard, online guidedProfile, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	state, err := snapshot.State()
	if err != nil || state.Progress.ReleaseReview == nil || state.Progress.FinalRelease != nil || !workflowV4CoordinatorDirectRelease(protocol) {
		return errors.New("an authenticated V5 frozen release review is required")
	}
	config, err := workflowV4HandoffConfig(online.Work, protocol.Definition.CeremonyID)
	if err != nil {
		return err
	}
	root, _ := snapshot.Root()
	manifest := workflowV4PublicSnapshot{Schema: "relay-public-snapshot-v1", Root: root, Files: snapshot.Files()}
	checkpoint := snapshot.Head().Record.Digest.SHA256
	if err := workflowV4ValidateReleaseSnapshot(manifest, protocol.Definition.CeremonyID, checkpoint); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(raw) > 16<<20 {
		return errors.New("release snapshot manifest exceeds 16 MiB")
	}
	path := workflowV4ReleaseSnapshotManifestPath(online.Work)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := requireOfflineRealPath(filepath.Dir(path)); err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(path, raw, 0600); err != nil {
		return fmt.Errorf("retained release snapshot differs: %w", err)
	}
	sha := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sha[:])
	var coordinator setupIdentity
	if err := setupReadJSON(filepath.Join(online.Keys, "identity.json"), &coordinator); err != nil || coordinator.Fingerprint == "" {
		return errors.New("coordinator public identity is unavailable for release handoff")
	}
	if err := ui.confirm("Publish this exact public release-review snapshot manifest to AWS for keyless signer download", "SEND RELEASE SNAPSHOT"); err != nil {
		return err
	}
	client, err := workflowV4BoundHostAWS(online, config, config.PublishedBucket)
	if err != nil {
		return err
	}
	if err := workflowV4HandoffPut(client, store.Key(digest), path, filepath.Dir(path), 16<<20); err != nil {
		return err
	}
	if err := workflowV4HandoffReadback(store.Client{PublicBaseURL: config.PublishedBaseURL}, store.Key(digest), path, filepath.Dir(path), 16<<20); err != nil {
		return fmt.Errorf("release snapshot is not publicly readable at the configured AWS origin: %w", err)
	}
	fmt.Fprintf(ui.output, "Public AWS release snapshot ready. Give the signer these exact values through your authenticated channel:\nPublic origin: %s\nCeremony: %s\nCoordinator fingerprint: %s\nSigned update: %d\nRelease-review checkpoint: %s\nSnapshot manifest SHA-256: %s\nThe signer must still verify the complete signed snapshot while offline.\n", config.PublishedBaseURL, protocol.Definition.CeremonyID, coordinator.Fingerprint, state.Sequence, checkpoint, digest)
	return nil
}

func workflowV4SignerDownloadReleaseSnapshot(ui *coordinatorWizard, work string) error {
	origin, err := ui.required("Coordinator's public AWS HTTPS origin", "")
	if err != nil {
		return err
	}
	if err := validateStorageFirstOrigin("release snapshot public origin", origin); err != nil {
		return err
	}
	ceremonyID, err := ui.required("Independently compared ceremony ID (sha256:...)", "")
	if err != nil {
		return err
	}
	checkpointSHA, err := ui.required("Independently compared release-review checkpoint SHA-256", "")
	if err != nil {
		return err
	}
	manifestSHA, err := ui.required("Independently compared snapshot manifest SHA-256", "")
	if err != nil {
		return err
	}
	for _, digest := range []string{ceremonyID, checkpointSHA, manifestSHA} {
		if _, err := workflowV4HandoffHex(digest); err != nil {
			return err
		}
	}
	stage, err := os.MkdirTemp(work, "incoming-release-*")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(stage)
		}
	}()
	public := store.Client{PublicBaseURL: origin}
	manifestPath := filepath.Join(stage, offlineSnapshotFile)
	if _, err := public.GetVersionedAtMost(store.Key(manifestSHA), manifestPath, 16<<20); err != nil {
		return err
	}
	got, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil || got != manifestSHA {
		return errors.New("downloaded release snapshot manifest differs from the compared hash")
	}
	raw, err := readTesseraRegularFile(manifestPath, 16<<20, false)
	if err != nil || rejectCommitJournalDuplicateFields(raw) != nil {
		return errors.New("invalid release snapshot manifest")
	}
	var manifest workflowV4PublicSnapshot
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := workflowV4ValidateReleaseSnapshot(manifest, ceremonyID, checkpointSHA); err != nil {
		return err
	}
	objects := filepath.Join(stage, "objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ref := range manifest.Files {
		if seen[ref.SHA256] {
			continue
		}
		seen[ref.SHA256] = true
		path := filepath.Join(objects, strings.TrimPrefix(ref.SHA256, "sha256:"))
		if _, err := public.GetVersionedAtMost(store.Key(ref.SHA256), path, ref.Size); err != nil {
			return fmt.Errorf("download snapshot object %s: %w", ref.Name, err)
		}
		sha, size, err := workflowV4FileSHA256(path, ref.Size)
		if err != nil || sha != ref.SHA256 || size != ref.Size {
			return fmt.Errorf("downloaded release snapshot object differs: %s", ref.Name)
		}
	}
	if _, err := openWorkflowV4OfflineStore(stage); err != nil {
		return err
	}
	complete = true
	fmt.Fprintf(ui.output, "Byte-checked public snapshot saved at %s. Disconnect this host, then open the release-signer guide and select this directory. Compare its signed update and coordinator-key fingerprint with the coordinator's independently provided values before signing.\n", stage)
	return nil
}

// This setup action runs after the offline signing guide has exited. It reads
// only public ceremony files and the temporary upload grant; the signing key
// directory is deliberately removed from every container profile it launches.
func workflowV4SignerUploadReleasePackage(ui *coordinatorWizard, profile guidedProfile, keys string) error {
	if profile.Role != "release-signer" || profile.Credentials != "" || profile.R2Parent != "" || profile.R2Control != "" {
		return errors.New("online release upload requires the keyless release-signer setup path")
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(keys, "identity.json"), &identity); err != nil || identity.ID == "" {
		return errors.New("the release-signer public identity is missing")
	}
	snapshotPath, err := ui.required("Directory of the exact release-review snapshot used for offline signing", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(snapshotPath) || filepath.Clean(snapshotPath) != snapshotPath {
		return errors.New("release snapshot path must be absolute and clean")
	}
	objects, err := openWorkflowV4OfflineStore(snapshotPath)
	if err != nil {
		return err
	}
	grantPath, err := ui.required("Absolute path to the private release upload grant (mode 0600, outside signer work, trust and keys)", "")
	if err != nil {
		return err
	}
	if err := workflowV4SignerGrantOutsideMounts(grantPath, profile.Work, profile.Trust, keys); err != nil {
		return err
	}
	grant, err := loadStorageFirstGrant(grantPath)
	if err != nil {
		return err
	}
	if grant.Provider != "aws" || grant.SubmissionKind != access.SubmissionKindRelease || grant.IdentityID != identity.ID ||
		grant.CeremonyID != objects.root.CeremonyID || grant.CheckpointDigest != objects.root.Checkpoint.SHA256 {
		return errors.New("private release grant differs from the offline signed snapshot or signer")
	}
	fmt.Fprintf(ui.output, "Online public-package upload destination: AWS bucket %s in %s. Ceremony: %s. Frozen review checkpoint: %s. Grant expires: %s. Compare the bucket and region with the coordinator's separately communicated values before approving upload.\n", grant.InboxBucket, grant.Region, grant.CeremonyID, grant.CheckpointDigest, grant.ExpiresAt)
	cli, err := exec.LookPath("docker")
	if err != nil {
		return err
	}
	cli, err = filepath.Abs(cli)
	if err != nil {
		return err
	}
	if err := prepareGuidedImage(profile.Image, profile.Platform, cli, false); err != nil {
		return err
	}
	profile.Keys = ""
	root := filepath.Join(profile.Work, "ceremony", "public")
	d := dockerDriver{runtimeLimits: profile.Resources, image: profile.Image, platform: profile.Platform, ceremonyBinary: dockerCeremonyBinary, root: root, inspectionRoot: profile.Work, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: filepath.Join(profile.Trust, "coordinator-public-key.hex"), client: osDockerCommandClient{binary: cli}}
	if err := d.authenticateDaemon(); err != nil {
		return err
	}
	inspector := d.inspector()
	protocol, err := inspector.DefinitionProtocol()
	if err != nil || !workflowV4CoordinatorDirectRelease(protocol) || protocol.Definition.CeremonyID != grant.CeremonyID {
		return errors.New("signed V5 definition differs from the release upload grant")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil || expected.Identity.ID != identity.ID || expected.Identity.KeyID != identity.KeyID {
		return errors.New("release upload identity differs from the signed assignment")
	}
	snapshot, err := syncWorkflowV4UploadStation(profile, d, inspector, protocol, objects)
	if err != nil {
		return fmt.Errorf("authenticate offline release snapshot before upload: %w", err)
	}
	state, err := snapshot.State()
	if err != nil || state.Progress.ReleaseReview == nil || state.Progress.FinalRelease != nil || snapshot.Head().Record.Digest.SHA256 != grant.CheckpointDigest {
		return errors.New("release upload grant does not match the frozen review checkpoint")
	}
	packageDir := filepath.Join(profile.Work, "workflow-v4", "release", workflowV4ReleasePackageDir)
	if err := workflowV4VerifyClosedReleasePackage(profile, packageDir, expected.Identity.KeyID); err != nil {
		return fmt.Errorf("verify signed public release package before upload: %w", err)
	}
	config := access.StorageConfig{Provider: grant.Provider, Endpoint: grant.Endpoint, Region: grant.Region, InboxBucket: grant.InboxBucket}
	progress := workflowV4ReleaseSignerProgress{PackageReady: true, PackageDir: packageDir}
	return runWorkflowV4ReleaseUploadWithGrant(ui, snapshot, protocol, config, profile, identity.ID, identity.KeyID, progress, grant)
}
