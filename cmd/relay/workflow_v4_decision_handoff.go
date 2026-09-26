package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// The handoff is transport metadata, never ceremony evidence. Its objects are
// checked again by the offline guide and the pinned decision verifier.
const workflowV4DecisionHandoffSchema = "relay-decision-handoff-v1"

type workflowV4DecisionHandoffFile struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type workflowV4DecisionHandoff struct {
	Schema           string                          `json:"schema"`
	CeremonyID       string                          `json:"ceremony_id"`
	CandidateID      string                          `json:"candidate_id"`
	CheckpointSHA256 string                          `json:"checkpoint_sha256"`
	DecisionSHA256   string                          `json:"decision_sha256"`
	SignerID         string                          `json:"signer_id"`
	PublishedBaseURL string                          `json:"published_base_url"`
	Snapshot         workflowV4PublicSnapshot        `json:"snapshot"`
	Files            []workflowV4DecisionHandoffFile `json:"files"`
}

type workflowV4SignerHandoffTransport struct {
	Schema           string `json:"schema"`
	CeremonyID       string `json:"ceremony_id"`
	CandidateID      string `json:"candidate_id"`
	CheckpointSHA256 string `json:"checkpoint_sha256"`
	DecisionSHA256   string `json:"decision_sha256"`
	SignerID         string `json:"signer_id"`
	Region           string `json:"region"`
	Bucket           string `json:"bucket"`
	ManifestKey      string `json:"manifest_key"`
	ManifestSHA256   string `json:"manifest_sha256"`
	SignatureKey     string `json:"signature_key"`
	SnapshotPath     string `json:"snapshot_path"`
}

func workflowV4HandoffHex(digest string) (string, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return "", errors.New("handoff digest must have a sha256 prefix")
	}
	value := strings.TrimPrefix(digest, "sha256:")
	bytes, err := hex.DecodeString(value)
	if err != nil || len(bytes) != sha256.Size || hex.EncodeToString(bytes) != value {
		return "", errors.New("handoff digest is not a canonical SHA-256")
	}
	return value, nil
}

func workflowV4HandoffPrefix(ceremonyID, decisionSHA string) (string, error) {
	ceremony, err := workflowV4HandoffHex(ceremonyID)
	if err != nil {
		return "", err
	}
	decision, err := workflowV4HandoffHex(decisionSHA)
	if err != nil {
		return "", err
	}
	return "handoff/decision/" + ceremony + "/" + decision, nil
}

func workflowV4HandoffObjectKey(prefix, digest string) (string, error) {
	value, err := workflowV4HandoffHex(digest)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(prefix, "handoff/decision/") || strings.Contains(prefix, "..") {
		return "", errors.New("invalid decision handoff prefix")
	}
	return prefix + "/objects/" + value, nil
}

func workflowV4SafeSignerID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func (m workflowV4DecisionHandoff) validate() error {
	if m.Schema != workflowV4DecisionHandoffSchema {
		return errors.New("unsupported decision handoff format")
	}
	prefix, err := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	if err != nil {
		return err
	}
	if _, err := workflowV4HandoffHex(m.CheckpointSHA256); err != nil {
		return err
	}
	if _, err := workflowV4HandoffHex(m.CandidateID); err != nil {
		return err
	}
	if !workflowV4SafeSignerID(m.SignerID) {
		return errors.New("invalid decision handoff signer")
	}
	if err := validateStorageFirstOrigin("decision handoff public origin", m.PublishedBaseURL); err != nil {
		return err
	}
	if m.Snapshot.Schema != "relay-public-snapshot-v1" || m.Snapshot.Root.CeremonyID != m.CeremonyID || len(m.Snapshot.Files) == 0 || len(m.Snapshot.Files) > 65536 {
		return errors.New("decision handoff snapshot does not match the ceremony")
	}
	if err := m.Snapshot.Root.Validate(); err != nil {
		return err
	}
	if m.Snapshot.Root.Checkpoint.SHA256 != m.CheckpointSHA256 {
		return errors.New("decision handoff checkpoint differs from its snapshot root")
	}
	snapshotNames := map[string]bool{}
	snapshotDigests := map[string]int64{}
	var snapshotTotal int64
	for _, ref := range m.Snapshot.Files {
		if _, err := workflowV4HandoffHex(ref.SHA256); err != nil || ref.Size <= 0 || ref.Size > 16<<30 || ref.Name == "" || ref.Name == "." || ref.Name == ".." || strings.HasPrefix(ref.Name, "../") || filepath.IsAbs(ref.Name) || filepath.ToSlash(filepath.Clean(ref.Name)) != ref.Name || strings.Contains(ref.Name, `\`) || snapshotNames[ref.Name] {
			return errors.New("invalid decision handoff snapshot reference")
		}
		snapshotNames[ref.Name] = true
		if size, exists := snapshotDigests[ref.SHA256]; exists && size != ref.Size {
			return errors.New("conflicting decision handoff snapshot digest")
		}
		snapshotDigests[ref.SHA256] = ref.Size
		if snapshotTotal > 64<<30-ref.Size {
			return errors.New("decision handoff snapshot exceeds 64 GiB")
		}
		snapshotTotal += ref.Size
	}
	if len(m.Files) < 2 || len(m.Files) > 1024 {
		return errors.New("invalid decision handoff file count")
	}
	seen := map[string]bool{}
	var total int64
	for _, file := range m.Files {
		if !strings.HasPrefix(file.Name, "decision/") || filepath.IsAbs(file.Name) || filepath.ToSlash(filepath.Clean(file.Name)) != file.Name || strings.Contains(file.Name, `\`) || seen[file.Name] || file.Size <= 0 || file.Size > 16<<20 {
			return fmt.Errorf("invalid decision handoff file %q", file.Name)
		}
		seen[file.Name] = true
		expected, err := workflowV4HandoffObjectKey(prefix, file.SHA256)
		if err != nil || file.Key != expected {
			return fmt.Errorf("invalid decision handoff object key for %q", file.Name)
		}
		total += file.Size
		if total > 1<<30 {
			return errors.New("decision handoff evidence exceeds the total bound")
		}
	}
	if !seen["decision/decision.json"] || !seen["decision/coordinator.sig"] {
		return errors.New("decision handoff lacks the decision or coordinator signature")
	}
	for _, file := range m.Files {
		if file.Name == "decision/decision.json" && file.SHA256 != m.DecisionSHA256 {
			return errors.New("decision handoff decision digest differs from its file inventory")
		}
	}
	return nil
}

func workflowV4FileSHA256(path string, maximum int64) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return "", 0, fmt.Errorf("invalid bounded regular handoff file %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil || size != info.Size() {
		return "", 0, errors.New("handoff file changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), size, nil
}

func workflowV4HandoffDecisionRelease(path, candidateID, checkpointSHA string, root state.Root) error {
	raw, err := readTesseraRegularFile(path, 16<<20, false)
	if err != nil {
		return err
	}
	var decision struct {
		Release struct {
			CandidateID            string                        `json:"candidate_id"`
			FinalReleaseCheckpoint transcript.SignedArtifactRefs `json:"final_release_checkpoint"`
		} `json:"release"`
	}
	if json.Unmarshal(raw, &decision) != nil || decision.Release.CandidateID != candidateID ||
		decision.Release.FinalReleaseCheckpoint.Record.Name != root.Checkpoint.Name ||
		decision.Release.FinalReleaseCheckpoint.Record.Digest.SHA256 != checkpointSHA ||
		decision.Release.FinalReleaseCheckpoint.Record.Digest.SHA256 != root.Checkpoint.SHA256 ||
		decision.Release.FinalReleaseCheckpoint.Record.Digest.Size != root.Checkpoint.Size ||
		decision.Release.FinalReleaseCheckpoint.Signature.Name != root.CheckpointSignature.Name ||
		decision.Release.FinalReleaseCheckpoint.Signature.Digest.SHA256 != root.CheckpointSignature.SHA256 ||
		decision.Release.FinalReleaseCheckpoint.Signature.Digest.Size != root.CheckpointSignature.Size {
		return errors.New("decision release differs from the exact signed-release handoff")
	}
	return nil
}

func workflowV4HandoffReadback(client store.Client, key, source, temporary string, maximum int64) error {
	wantSHA, wantSize, err := workflowV4FileSHA256(source, maximum)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(temporary, ".decision-handoff-readback-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "object")
	if _, err := client.GetVersionedAtMost(key, path, maximum); err != nil {
		return err
	}
	gotSHA, gotSize, err := workflowV4FileSHA256(path, maximum)
	if err != nil || gotSHA != wantSHA || gotSize != wantSize {
		return errors.New("AWS handoff readback differs from retained bytes")
	}
	return nil
}

func workflowV4HandoffPut(client store.Client, key, source, temporary string, maximum int64) error {
	if _, _, err := workflowV4FileSHA256(source, maximum); err != nil {
		return err
	}
	if err := client.PutLargeNoReplace(key, source, temporary); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return workflowV4HandoffReadback(client, key, source, temporary, maximum)
}

func workflowV4DecodeHandoff(raw []byte) (workflowV4DecisionHandoff, error) {
	var manifest workflowV4DecisionHandoff
	if len(raw) == 0 || len(raw) > 16<<20 || rejectCommitJournalDuplicateFields(raw) != nil {
		return manifest, errors.New("invalid decision handoff manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
		return manifest, errors.New("invalid decision handoff manifest")
	}
	return manifest, manifest.validate()
}

func workflowV4HandoffConfig(work string, ceremonyID string) (access.StorageConfig, error) {
	config, err := loadStorageConfig(filepath.Join(work, "ceremony", "config", "relay-storage.json"))
	if err != nil {
		return config, err
	}
	if config.Provider != "aws" || config.CeremonyID != ceremonyID || config.InboxBucket == "" || config.CoordinatorProfile == "" {
		return config, errors.New("decision AWS handoff requires matching reviewed AWS coordinator settings")
	}
	return config, config.Validate()
}

func workflowV4HandoffManifestPath(work string) string {
	return filepath.Join(work, "workflow-v4", "decision-handoff", "manifest.json")
}

func runWorkflowV4PublishDecisionHandoff(ui *coordinatorWizard, online guidedProfile, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	state, err := snapshot.State()
	if err != nil || state.Progress.FinalRelease == nil {
		return errors.New("the signed final release must be recorded before sending a decision handoff")
	}
	if snapshot.Head().Record.Digest.SHA256 == "" {
		return errors.New("an authenticated final checkpoint is required for decision handoff")
	}
	config, err := workflowV4HandoffConfig(online.Work, protocol.Definition.CeremonyID)
	if err != nil {
		return err
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		return err
	}
	root := filepath.Join(online.Work, "ceremony", "public")
	if _, err := os.Lstat(filepath.Join(root, "decision", "release-signer.sig")); err == nil {
		return errors.New("the release signer has already returned a signature; do not create a new decision handoff")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	files, _, err := workflowV4DecisionArchiveFiles(root)
	if err != nil {
		return fmt.Errorf("canonical signed decision handoff: %w", err)
	}
	decisionSHA, _, err := workflowV4FileSHA256(filepath.Join(root, "decision", "decision.json"), 16<<20)
	if err != nil {
		return err
	}
	candidateID, err := workflowV4CandidateID(snapshot, online.Work)
	if err != nil {
		return err
	}
	snapshotRoot, _ := snapshot.Root()
	if err := workflowV4HandoffDecisionRelease(filepath.Join(root, "decision", "decision.json"), candidateID, snapshot.Head().Record.Digest.SHA256, snapshotRoot); err != nil {
		return err
	}
	prefix, err := workflowV4HandoffPrefix(protocol.Definition.CeremonyID, decisionSHA)
	if err != nil {
		return err
	}
	manifest := workflowV4DecisionHandoff{Schema: workflowV4DecisionHandoffSchema, CeremonyID: protocol.Definition.CeremonyID, CandidateID: candidateID, CheckpointSHA256: snapshot.Head().Record.Digest.SHA256, DecisionSHA256: decisionSHA, SignerID: expected.Identity.ID, PublishedBaseURL: config.PublishedBaseURL, Snapshot: workflowV4PublicSnapshot{Schema: "relay-public-snapshot-v1", Root: snapshotRoot, Files: snapshot.Files()}}
	for _, name := range files {
		sha, size, err := workflowV4FileSHA256(filepath.Join(root, filepath.FromSlash(name)), 16<<20)
		if err != nil {
			return err
		}
		key, err := workflowV4HandoffObjectKey(prefix, sha)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, workflowV4DecisionHandoffFile{Name: name, Key: key, SHA256: sha, Size: size})
	}
	if err := manifest.validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(raw) > 16<<20 {
		return errors.New("decision handoff manifest exceeds its bound")
	}
	manifestPath := workflowV4HandoffManifestPath(online.Work)
	if err := workflowV4HandoffEnsureDir(filepath.Join(online.Work, "workflow-v4")); err != nil {
		return err
	}
	if err := workflowV4HandoffEnsureDir(filepath.Dir(manifestPath)); err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(manifestPath, raw, 0600); err != nil {
		return err
	}
	if err := ui.confirm("Upload the exact public decision and referenced evidence to the private AWS handoff; no signing key is used", "SEND DECISION PACKET"); err != nil {
		return err
	}
	client := store.Client{Profile: config.CoordinatorProfile, Region: config.Region, Endpoint: config.Endpoint, Bucket: config.InboxBucket}
	for _, file := range manifest.Files {
		if err := workflowV4HandoffPut(client, file.Key, filepath.Join(root, filepath.FromSlash(file.Name)), filepath.Dir(manifestPath), 16<<20); err != nil {
			return fmt.Errorf("send decision handoff %s: %w", file.Name, err)
		}
	}
	manifestKey := prefix + "/manifest.json"
	if err := workflowV4HandoffPut(client, manifestKey, manifestPath, filepath.Dir(manifestPath), 16<<20); err != nil {
		return fmt.Errorf("send decision handoff completion manifest: %w", err)
	}
	manifestSHA, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Private AWS decision handoff ready. Give the release signer the bucket, region, manifest key and digest through the agreed channel.\nCeremony: %s\nCandidate: %s\nFinal checkpoint: %s\nDecision: %s\nBucket: %s\nRegion: %s\nManifest key: %s\nManifest SHA-256: %s\n", manifest.CeremonyID, manifest.CandidateID, manifest.CheckpointSHA256, manifest.DecisionSHA256, config.InboxBucket, config.Region, manifestKey, manifestSHA)
	return nil
}

func runWorkflowV4FetchDecisionSignature(ui *coordinatorWizard, online guidedProfile, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	config, err := workflowV4HandoffConfig(online.Work, protocol.Definition.CeremonyID)
	if err != nil {
		return err
	}
	raw, err := readTesseraRegularFile(workflowV4HandoffManifestPath(online.Work), 16<<20, false)
	if err != nil {
		return fmt.Errorf("retained AWS decision handoff: %w", err)
	}
	manifest, err := workflowV4DecodeHandoff(raw)
	if err != nil || manifest.CeremonyID != protocol.Definition.CeremonyID || manifest.CheckpointSHA256 != snapshot.Head().Record.Digest.SHA256 {
		return errors.New("retained decision handoff does not match this authenticated release")
	}
	candidateID, err := workflowV4CandidateID(snapshot, online.Work)
	if err != nil || manifest.CandidateID != candidateID {
		return errors.New("retained decision handoff does not match the authenticated candidate")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil || manifest.SignerID != expected.Identity.ID {
		return errors.New("retained decision handoff does not match the authenticated release-signer assignment")
	}
	decisionSHA, _, err := workflowV4FileSHA256(filepath.Join(online.Work, "ceremony", "public", "decision", "decision.json"), 16<<20)
	if err != nil || decisionSHA != manifest.DecisionSHA256 {
		return errors.New("canonical decision changed after AWS handoff")
	}
	if err := workflowV4HandoffDecisionRelease(filepath.Join(online.Work, "ceremony", "public", "decision", "decision.json"), manifest.CandidateID, manifest.CheckpointSHA256, manifest.Snapshot.Root); err != nil {
		return err
	}
	prefix, _ := workflowV4HandoffPrefix(manifest.CeremonyID, manifest.DecisionSHA256)
	key := prefix + "/signatures/" + manifest.SignerID + ".sig"
	client := store.Client{Profile: config.CoordinatorProfile, Region: config.Region, Endpoint: config.Endpoint, Bucket: config.InboxBucket}
	dir := filepath.Dir(workflowV4HandoffManifestPath(online.Work))
	temporary, err := os.MkdirTemp(dir, ".signature-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	path := filepath.Join(temporary, "release-signer.sig")
	if _, err := client.GetVersionedAtMost(key, path, 16<<20); err != nil {
		return fmt.Errorf("fetch release signer public decision signature: %w", err)
	}
	bytes, err := readTesseraRegularFile(path, 16<<20, false)
	if err != nil {
		return err
	}
	var signature struct {
		Role     string `json:"role"`
		SignerID string `json:"signer_id"`
	}
	if json.Unmarshal(bytes, &signature) != nil || signature.Role != "release_signer" || signature.SignerID != manifest.SignerID {
		return errors.New("returned public signature has the wrong role or signer identity")
	}
	destination := filepath.Join(online.Work, "ceremony", "public", "decision", "release-signer.sig")
	if err := setupWriteBytesNewOrExact(destination, bytes, 0600); err != nil {
		return fmt.Errorf("retain exact returned signature without replacement: %w", err)
	}
	sha, _, err := workflowV4FileSHA256(destination, 16<<20)
	if err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Fetched public signature: %s\nSHA-256: %s\nChoose D → 3 to verify the complete required signature set with pinned proof-tool. Fetch alone does not approve the decision.\n", destination, sha)
	return nil
}

func runWorkflowV4SignerDecisionHandoff(ui *coordinatorWizard, work, publicIdentityPath string) error {
	var identity setupIdentity
	if err := setupReadJSON(publicIdentityPath, &identity); err != nil || identity.ID == "" {
		return errors.New("generate and review your public release-signer identity before AWS decision handoff")
	}
	fmt.Fprintln(ui.output, "ONLINE, KEYLESS TRANSFER. Exit the offline signing guide before using this action. It never opens your signing key or launches a signing container.\n1) Download the coordinator's decision packet from AWS\n2) Upload my already-signed PUBLIC decision signature to AWS\n0) Back")
	choice, err := ui.ask("Choose a transfer action", "")
	if err != nil {
		return err
	}
	switch choice {
	case "0", "":
		return nil
	case "1":
		return workflowV4SignerDownloadDecision(ui, work, identity.ID)
	case "2":
		return workflowV4SignerUploadDecisionSignature(ui, work, identity.ID)
	default:
		return errors.New("choose a listed decision transfer action")
	}
}

func workflowV4SignerTransportPath(work string) string {
	return filepath.Join(work, "workflow-v4", "decision-handoff", "transport.json")
}

func workflowV4DecisionGrantMatchesTransport(grant workflowV4DecisionTransferGrant, transport workflowV4SignerHandoffTransport) bool {
	return grant.CeremonyID == transport.CeremonyID && grant.CandidateID == transport.CandidateID &&
		grant.CheckpointSHA256 == transport.CheckpointSHA256 && grant.DecisionSHA256 == transport.DecisionSHA256 &&
		grant.ManifestSHA256 == transport.ManifestSHA256 && grant.ManifestKey == transport.ManifestKey &&
		grant.SignatureKey == transport.SignatureKey && grant.SignerID == transport.SignerID &&
		grant.Region == transport.Region && grant.InboxBucket == transport.Bucket
}

func workflowV4HandoffEnsureDir(path string) error {
	parent := filepath.Dir(path)
	if path == parent {
		return errors.New("invalid handoff directory")
	}
	if err := requireOfflineRealPath(parent); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return requireOfflineRealPath(path)
}

func workflowV4SignerDownloadDecision(ui *coordinatorWizard, work, signerID string) error {
	grantPath, err := ui.required("Absolute path to the coordinator's PRIVATE download grant (mode 0600)", "")
	if err != nil {
		return err
	}
	if err := workflowV4SignerGrantOutsideWork(grantPath, work); err != nil {
		return err
	}
	grant, err := workflowV4LoadDecisionTransferGrant(grantPath, "download", signerID)
	if err != nil {
		return err
	}
	ceremonyID, checkpointSHA, decisionSHA := grant.CeremonyID, grant.CheckpointSHA256, grant.DecisionSHA256
	manifestSHA, manifestKey := grant.ManifestSHA256, grant.ManifestKey
	fmt.Fprintf(ui.output, "Private download grant expires %s. Compare ceremony %s, final checkpoint %s, decision %s, and manifest %s with the coordinator's separately communicated values before offline signing. This grant is transport access, not proof of authenticity.\n", grant.ExpiresAt, ceremonyID, checkpointSHA, decisionSHA, manifestSHA)
	base := filepath.Dir(workflowV4SignerTransportPath(work))
	if err := workflowV4HandoffEnsureDir(filepath.Join(work, "workflow-v4")); err != nil {
		return err
	}
	if err := workflowV4HandoffEnsureDir(base); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(work, "incoming-decision-*")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(stage)
		}
	}()
	client := workflowV4DecisionGrantClient(grant)
	manifestPath := filepath.Join(stage, "handoff-manifest.json")
	if _, err := client.GetVersionedAtMost(manifestKey, manifestPath, 16<<20); err != nil {
		return err
	}
	gotManifestSHA, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil || gotManifestSHA != manifestSHA {
		return errors.New("AWS decision handoff manifest differs from the independently compared digest")
	}
	raw, err := readTesseraRegularFile(manifestPath, 16<<20, false)
	if err != nil {
		return err
	}
	manifest, err := workflowV4DecodeHandoff(raw)
	if err != nil || manifest.CeremonyID != ceremonyID || manifest.CandidateID != grant.CandidateID || manifest.CheckpointSHA256 != checkpointSHA || manifest.DecisionSHA256 != decisionSHA || manifest.SignerID != signerID {
		return errors.New("AWS decision handoff does not match the selected ceremony, checkpoint and decision")
	}
	var snapshotBytes int64
	for _, ref := range manifest.Snapshot.Files {
		if ref.Size <= 0 || ref.Size > 16<<30 || snapshotBytes > 64<<30-ref.Size {
			return errors.New("AWS decision handoff snapshot exceeds the download bound")
		}
		snapshotBytes += ref.Size
	}
	if snapshotBytes > 64<<30 {
		return errors.New("AWS decision handoff snapshot exceeds 64 GiB")
	}
	snapshotDir := filepath.Join(stage, "snapshot")
	objectsDir := filepath.Join(snapshotDir, "objects")
	if err := workflowV4HandoffEnsureDir(snapshotDir); err != nil {
		return err
	}
	if err := workflowV4HandoffEnsureDir(objectsDir); err != nil {
		return err
	}
	public := store.Client{PublicBaseURL: manifest.PublishedBaseURL}
	seen := map[string]bool{}
	for _, ref := range manifest.Snapshot.Files {
		key := store.Key(ref.SHA256)
		if seen[key] {
			continue
		}
		seen[key] = true
		path := filepath.Join(objectsDir, strings.TrimPrefix(ref.SHA256, "sha256:"))
		if _, err := public.GetVersionedAtMost(key, path, ref.Size); err != nil {
			return fmt.Errorf("download authenticated-snapshot candidate %s: %w", ref.Name, err)
		}
		sha, size, err := workflowV4FileSHA256(path, ref.Size)
		if err != nil || sha != ref.SHA256 || size != ref.Size {
			return fmt.Errorf("downloaded snapshot object differs: %s", ref.Name)
		}
	}
	snapshotRaw, err := json.MarshalIndent(manifest.Snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(filepath.Join(snapshotDir, offlineSnapshotFile), snapshotRaw, 0600); err != nil {
		return err
	}
	if _, err := openWorkflowV4OfflineStore(snapshotDir); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		path := filepath.Join(stage, filepath.FromSlash(file.Name))
		if err := workflowV4HandoffEnsureDir(filepath.Join(stage, "decision")); err != nil {
			return err
		}
		if strings.HasPrefix(file.Name, "decision/evidence/") {
			if err := workflowV4HandoffEnsureDir(filepath.Join(stage, "decision", "evidence")); err != nil {
				return err
			}
		}
		if filepath.Dir(path) != filepath.Join(stage, "decision") && filepath.Dir(path) != filepath.Join(stage, "decision", "evidence") {
			return errors.New("nested decision handoff evidence directories are unsupported")
		}
		if err := requireOfflineRealPath(filepath.Dir(path)); err != nil {
			return err
		}
		if _, err := client.GetVersionedAtMost(file.Key, path, file.Size); err != nil {
			return err
		}
		sha, size, err := workflowV4FileSHA256(path, file.Size)
		if err != nil || sha != file.SHA256 || size != file.Size {
			return fmt.Errorf("AWS decision handoff file differs: %s", file.Name)
		}
	}
	if _, _, err := workflowV4DecisionArchiveFiles(stage); err != nil {
		return fmt.Errorf("downloaded decision inventory: %w", err)
	}
	if err := workflowV4HandoffDecisionRelease(filepath.Join(stage, "decision", "decision.json"), manifest.CandidateID, manifest.CheckpointSHA256, manifest.Snapshot.Root); err != nil {
		return err
	}
	canonicalDir := filepath.Join(work, "ceremony", "public", "decision")
	if err := workflowV4HandoffEnsureDir(canonicalDir); err != nil {
		return err
	}
	if err := workflowV4HandoffEnsureDir(filepath.Join(canonicalDir, "evidence")); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		source := filepath.Join(stage, filepath.FromSlash(file.Name))
		bytes, err := readTesseraRegularFile(source, file.Size, false)
		if err != nil {
			return err
		}
		destination := filepath.Join(work, "ceremony", "public", filepath.FromSlash(file.Name))
		if err := requireOfflineRealPath(filepath.Dir(destination)); err != nil {
			return err
		}
		if err := setupWriteBytesNewOrExact(destination, bytes, 0600); err != nil {
			return fmt.Errorf("retain decision packet without replacing existing file: %w", err)
		}
	}
	transport := workflowV4SignerHandoffTransport{Schema: "relay-signer-decision-transport-v1", CeremonyID: grant.CeremonyID, CandidateID: grant.CandidateID, CheckpointSHA256: grant.CheckpointSHA256, DecisionSHA256: grant.DecisionSHA256, SignerID: signerID, Region: grant.Region, Bucket: grant.InboxBucket, ManifestKey: manifestKey, ManifestSHA256: manifestSHA, SignatureKey: grant.SignatureKey, SnapshotPath: snapshotDir}
	transportRaw, err := json.Marshal(transport)
	if err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(workflowV4SignerTransportPath(work), transportRaw, 0600); err != nil {
		return err
	}
	complete = true
	fmt.Fprintf(ui.output, "Decision packet downloaded. Its bytes and transport manifest match the supplied hashes; the offline guide must still authenticate the signed snapshot and decision.\nSnapshot path for start.sh → 5: %s\nDecision: %s\nFinal checkpoint: %s\nExit, disconnect all networks, then open the offline signing guide.\n", snapshotDir, decisionSHA, checkpointSHA)
	return nil
}

func workflowV4SignerUploadDecisionSignature(ui *coordinatorWizard, work, signerID string) error {
	var transport workflowV4SignerHandoffTransport
	if err := setupReadJSON(workflowV4SignerTransportPath(work), &transport); err != nil {
		return err
	}
	if transport.Schema != "relay-signer-decision-transport-v1" || transport.SignerID != signerID || transport.Bucket == "" || transport.Region == "" {
		return errors.New("missing or invalid retained signer AWS transport settings")
	}
	grantPath, err := ui.required("Absolute path to the coordinator's PRIVATE upload grant (mode 0600); request a fresh grant if the old one expired", "")
	if err != nil {
		return err
	}
	if err := workflowV4SignerGrantOutsideWork(grantPath, work); err != nil {
		return err
	}
	grant, err := workflowV4LoadDecisionTransferGrant(grantPath, "upload", signerID)
	if err != nil {
		return fmt.Errorf("upload access stopped; retain the existing public signature and request a fresh upload grant if needed: %w", err)
	}
	if !workflowV4DecisionGrantMatchesTransport(grant, transport) {
		return errors.New("upload grant differs from the exact downloaded decision packet")
	}
	manifestPath := filepath.Join(filepath.Dir(transport.SnapshotPath), "handoff-manifest.json")
	retainedSHA, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil || retainedSHA != transport.ManifestSHA256 {
		return errors.New("retained signer handoff manifest changed before signature upload")
	}
	raw, err := readTesseraRegularFile(manifestPath, 16<<20, false)
	if err != nil {
		return err
	}
	manifest, err := workflowV4DecodeHandoff(raw)
	if err != nil {
		return err
	}
	if manifest.SignerID != signerID {
		return errors.New("retained decision handoff belongs to another release signer")
	}
	prefix, err := workflowV4HandoffPrefix(manifest.CeremonyID, manifest.DecisionSHA256)
	if err != nil || transport.ManifestKey != prefix+"/manifest.json" {
		return errors.New("retained signer transport differs from the decision")
	}
	decisionPath := filepath.Join(work, "ceremony", "public", "decision", "decision.json")
	decisionSHA, _, err := workflowV4FileSHA256(decisionPath, 16<<20)
	if err != nil || decisionSHA != manifest.DecisionSHA256 {
		return errors.New("canonical decision differs from the downloaded handoff")
	}
	if err := workflowV4HandoffDecisionRelease(decisionPath, manifest.CandidateID, manifest.CheckpointSHA256, manifest.Snapshot.Root); err != nil {
		return err
	}
	signaturePath := filepath.Join(work, "ceremony", "public", "decision", "release-signer.sig")
	bytes, err := readTesseraRegularFile(signaturePath, 16<<20, false)
	if err != nil {
		return fmt.Errorf("sign this decision offline before uploading its public signature: %w", err)
	}
	var signature struct {
		Role     string `json:"role"`
		SignerID string `json:"signer_id"`
	}
	if json.Unmarshal(bytes, &signature) != nil || signature.Role != "release_signer" || signature.SignerID != manifest.SignerID {
		return errors.New("public signature has the wrong signer role or identity")
	}
	sha, _, err := workflowV4FileSHA256(signaturePath, 16<<20)
	if err != nil {
		return err
	}
	key := prefix + "/signatures/" + manifest.SignerID + ".sig"
	fmt.Fprintf(ui.output, "Upload only this public signature to the private AWS handoff:\nCeremony: %s\nDecision: %s\nSignature SHA-256: %s\nBucket: %s\nKey: %s\n", manifest.CeremonyID, manifest.DecisionSHA256, sha, transport.Bucket, key)
	if err := ui.confirm("Reconnect only after offline signing has finished; this transfer does not use your signing key", "UPLOAD PUBLIC SIGNATURE"); err != nil {
		return err
	}
	client := workflowV4DecisionGrantClient(grant)
	if err := workflowV4HandoffPut(client, key, signaturePath, filepath.Dir(workflowV4SignerTransportPath(work)), 16<<20); err != nil {
		return err
	}
	fmt.Fprintf(ui.output, "Uploaded and read back exact public decision signature. Tell the coordinator to choose D → 5, then D → 3. Upload alone does not approve the decision.\n")
	return nil
}
