package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// TestV4LiveInitialR2 is an explicit live-provider check. It creates a unique
// tiny rehearsal definition, publishes its complete initial V4 state through
// the real R2 S3 API, and authenticates it back. It never uses production keys.
func TestV4LiveInitialR2(t *testing.T) {
	image := os.Getenv("RELAY_PREPARE_TEST_IMAGE")
	onlineImage := os.Getenv("RELAY_V4_LIVE_ONLINE_IMAGE")
	configPath := os.Getenv("RELAY_V4_LIVE_R2_CONFIG")
	credentialsPath := os.Getenv("RELAY_V4_LIVE_R2_CREDENTIALS")
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	if image == "" || onlineImage == "" || configPath == "" || credentialsPath == "" || proofBinary == "" {
		t.Skip("set RELAY_PREPARE_TEST_IMAGE, RELAY_V4_LIVE_ONLINE_IMAGE, RELAY_V4_LIVE_R2_CONFIG, RELAY_V4_LIVE_R2_CREDENTIALS and RELAY_V4_LIVE_PROOF_BINARY")
	}
	for _, path := range []string{configPath, credentialsPath, proofBinary} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("live test paths must be absolute and clean")
		}
	}
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	base, err := access.Decode(rawConfig, access.StorageConfig.Validate)
	if err != nil || base.Provider != "r2" {
		t.Fatalf("live test requires an existing valid R2 configuration: %v", err)
	}
	w := setupFixture(t)
	// On macOS the live test authenticates the initialized Linux ceremony with
	// a separately built native verifier. Include that exact companion in the
	// signed rehearsal allowlist just as the coordinator setup does for mixed
	// platforms. Linux runs use the image's primary binary and must not add a
	// duplicate platform entry.
	if runtime.GOOS != "linux" {
		digest, err := setupFileHash(proofBinary)
		if err != nil {
			t.Fatal(err)
		}
		w.d.Binaries = []setupBinary{{Path: proofBinary, SHA256: digest}}
	}
	w.d.Policy.Assurance = &setupAssurance{}
	w.d.Identities.Auditors = nil
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	var command []string
	w.run = func(args []string) error {
		if len(args) > 1 && args[1] == "setup" {
			for n, value := range args {
				if value == "--" {
					command = append([]string(nil), args[n+1:]...)
					return nil
				}
			}
			return errors.New("missing tool command")
		}
		platform, err := machineDockerPlatform()
		if err != nil {
			return err
		}
		argv, err := dockerRoleArgs(dockerRoleOptions{role: "coordinator", image: image, platform: platform, work: w.d.Work, trust: w.d.Trust, keys: w.d.Keys}, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		output, err := exec.Command("docker", argv...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, output)
		}
		return nil
	}
	if err := w.initialize(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(w.d.Work, "ceremony", "public")
	inspector := transcript.Inspector{Executable: proofBinary, CeremonyPath: filepath.Join(root, "ceremony.json"), CeremonySignaturePath: filepath.Join(root, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(w.d.Trust, "setup-coordinator.hex"), TranscriptRoot: root}
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	config := base
	config.CeremonyID = protocol.Definition.CeremonyID
	config.CeremonyPath = "/work/ceremony/public/ceremony.json"
	config.CeremonySignature = "/work/ceremony/public/ceremony.sig"
	config.CoordinatorPublicKey = "/trust/setup-coordinator.hex"
	config.CeremonyBinary = "/usr/local/bin/mpc-ceremony"
	storagePath := filepath.Join(w.d.Work, "ceremony", "config", "relay-storage.json")
	if err := writeJSONNoReplace(storagePath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	platform, err := machineDockerPlatform()
	if err != nil {
		t.Fatal(err)
	}
	commitCommand := []string{"relay", "coordinator", "commit-v4",
		"--storage", "/work/ceremony/config/relay-storage.json",
		"--artifact-root", "/work/ceremony/public",
		"--checkpoint", "/work/ceremony/public/checkpoints/initial/checkpoint.json",
		"--checkpoint-signature", "/work/ceremony/public/checkpoints/initial/checkpoint.sig",
		"--ceremony", config.CeremonyPath,
		"--ceremony-signature", config.CeremonySignature,
		"--coordinator-key", config.CoordinatorPublicKey,
		"--ceremony-binary", config.CeremonyBinary,
	}
	onlineArgs, err := dockerRoleArgs(dockerRoleOptions{role: "coordinator", image: onlineImage, platform: platform, work: w.d.Work, trust: w.d.Trust, keys: w.d.Keys, credentials: credentialsPath}, commitCommand, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("docker", onlineArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("commit initial live state: %v: %s", err, output)
	}
	highWater, err := state.OpenWorkspaceHighWater(filepath.Join(w.d.Work, "live-sync"), protocol.Definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	// The live check downloads checkpoint history into a fresh directory under
	// the role work root. Mount that work root read-only so the Docker proof
	// verifier can authenticate both the trusted definition and downloaded
	// state without exposing keys or credentials.
	driver := &dockerDriver{image: image, platform: platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: w.d.Work, definition: inspector.CeremonyPath, definitionSig: inspector.CeremonySignaturePath, coordinatorKey: inspector.CoordinatorPublicKeyPath, client: osDockerCommandClient{binary: "docker"}}
	snapshot, err := storagefirst.SyncV4(store.Client{PublicBaseURL: config.PublishedBaseURL}, driver.inspector(), highWater, protocol.Definition.CeremonyID, w.d.Work)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := snapshot.State()
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Sequence != 0 || checkpoint.Transition.Kind != "initial" || snapshot.Checked() != 1 {
		t.Fatalf("unexpected authenticated live initial state: sequence=%d transition=%s history=%d", checkpoint.Sequence, checkpoint.Transition.Kind, snapshot.Checked())
	}
	t.Logf("authenticated live R2 initial V4 state for ceremony %s", protocol.Definition.CeremonyID)
}

// TestV4LiveReleaseR2 is an explicit live-provider check for the last private
// handoff. It validates a retained V4 release grant against the authenticated
// frozen review, uploads a complete signed package, downloads it through the
// coordinator's inbox access, and authenticates the downloaded package with
// proof-tool. It never publishes the package.
func TestV4LiveReleaseR2(t *testing.T) {
	configPath := os.Getenv("RELAY_V4_LIVE_R2_CONFIG")
	credentialsPath := os.Getenv("RELAY_V4_LIVE_R2_CREDENTIALS")
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	ceremonyRoot := os.Getenv("RELAY_V4_LIVE_CEREMONY_ROOT")
	coordinatorKey := os.Getenv("RELAY_V4_LIVE_COORDINATOR_KEY")
	packageDir := os.Getenv("RELAY_V4_LIVE_RELEASE_PACKAGE")
	grantPath := os.Getenv("RELAY_V4_LIVE_RELEASE_GRANT")
	if configPath == "" || credentialsPath == "" || proofBinary == "" || ceremonyRoot == "" || coordinatorKey == "" || packageDir == "" || grantPath == "" {
		t.Skip("set the RELAY_V4_LIVE_R2_CONFIG, RELAY_V4_LIVE_R2_CREDENTIALS, RELAY_V4_LIVE_PROOF_BINARY, RELAY_V4_LIVE_CEREMONY_ROOT, RELAY_V4_LIVE_COORDINATOR_KEY, RELAY_V4_LIVE_RELEASE_PACKAGE and RELAY_V4_LIVE_RELEASE_GRANT paths")
	}
	for _, path := range []string{configPath, credentialsPath, proofBinary, ceremonyRoot, coordinatorKey, packageDir, grantPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("live test paths must be absolute and clean")
		}
	}
	config, err := loadStorageConfig(configPath)
	if err != nil || config.Provider != "r2" {
		t.Fatalf("live test requires an existing valid R2 configuration: %v", err)
	}
	inspector := transcript.Inspector{
		Executable:               proofBinary,
		CeremonyPath:             filepath.Join(ceremonyRoot, "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(ceremonyRoot, "ceremony.sig"),
		CoordinatorPublicKeyPath: coordinatorKey,
		TranscriptRoot:           ceremonyRoot,
	}
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Definition.CeremonyID != config.CeremonyID {
		t.Fatal("live R2 configuration belongs to another ceremony")
	}
	releaseSigner, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	if err := os.Chmod(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	highWater, err := state.OpenWorkspaceHighWater(filepath.Join(workspace, "high-water"), protocol.Definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagefirst.SyncV4(store.Client{PublicBaseURL: config.PublishedBaseURL}, inspector, highWater, protocol.Definition.CeremonyID, workspace)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := loadStorageFirstGrant(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	if err := storagefirst.ValidateReleaseGrantV4At(snapshot, protocol, releaseSigner.Identity.ID, grant, destination, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	inventory, sources, paths, err := workflowV4ReleaseFiles(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	scope := storagefirst.DeliveryScope{CeremonyID: grant.CeremonyID, AttemptID: grant.AttemptID, Kind: access.SubmissionKindRelease}
	uploadTemp := filepath.Join(workspace, "upload")
	if err := os.Mkdir(uploadTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := storagefirst.UploadDelivery(storageFirstGrantClient(grant), scope, inventory, sources, paths, uploadTemp); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	downloaded := filepath.Join(workspace, "downloaded-release")
	if err := runCoordinatorFetchReleaseV4([]string{"--storage", configPath, "--attempt-id", grant.AttemptID, "--out-dir", downloaded}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(proofBinary, "release", "verify",
		"--ceremony", inspector.CeremonyPath,
		"--ceremony-signature", inspector.CeremonySignaturePath,
		"--coordinator-public-key-file", coordinatorKey,
		"--keys-dir", downloaded,
		"--manifest-public-key-file", filepath.Join(downloaded, "manifest-public-key.hex"),
		"--signature-key-id", releaseSigner.Identity.KeyID,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("authenticate downloaded release package: %v: %s", err, output)
	}
	t.Logf("uploaded, downloaded and authenticated release package for ceremony %s", protocol.Definition.CeremonyID)
}

// TestV4LiveFinalizeReleaseR2 records the proof-authenticated package as the
// final signed checkpoint, publishes that checkpoint and all newly referenced
// public files, then proves a fresh client can reconstruct the terminal state.
func TestV4LiveFinalizeReleaseR2(t *testing.T) {
	configPath := os.Getenv("RELAY_V4_LIVE_R2_CONFIG")
	credentialsPath := os.Getenv("RELAY_V4_LIVE_R2_CREDENTIALS")
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	ceremonyRoot := os.Getenv("RELAY_V4_LIVE_CEREMONY_ROOT")
	coordinatorKey := os.Getenv("RELAY_V4_LIVE_COORDINATOR_KEY")
	coordinatorSigningKey := os.Getenv("RELAY_V4_LIVE_COORDINATOR_SIGNING_KEY")
	packageDir := os.Getenv("RELAY_V4_LIVE_RELEASE_PACKAGE")
	if configPath == "" || credentialsPath == "" || proofBinary == "" || ceremonyRoot == "" || coordinatorKey == "" || coordinatorSigningKey == "" || packageDir == "" {
		t.Skip("set the V4 live R2, proof, ceremony, coordinator and release-package paths")
	}
	for _, path := range []string{configPath, credentialsPath, proofBinary, ceremonyRoot, coordinatorKey, coordinatorSigningKey, packageDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("live test paths must be absolute and clean")
		}
	}
	config, err := loadStorageConfig(configPath)
	if err != nil || config.Provider != "r2" {
		t.Fatalf("live test requires an existing valid R2 configuration: %v", err)
	}
	inspector := transcript.Inspector{Executable: proofBinary, CeremonyPath: filepath.Join(ceremonyRoot, "ceremony.json"), CeremonySignaturePath: filepath.Join(ceremonyRoot, "ceremony.sig"), CoordinatorPublicKeyPath: coordinatorKey, TranscriptRoot: ceremonyRoot}
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	if err := os.Chmod(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	sync := func(name string) storagefirst.SnapshotV4 {
		t.Helper()
		highWater, err := state.OpenWorkspaceHighWater(filepath.Join(workspace, name), protocol.Definition.CeremonyID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := storagefirst.SyncV4(store.Client{PublicBaseURL: config.PublishedBaseURL}, inspector, highWater, protocol.Definition.CeremonyID, workspace)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	snapshot := sync("before")
	stateView, err := snapshot.State()
	if err != nil {
		t.Fatal(err)
	}
	if stateView.Progress.FinalRelease != nil {
		t.Logf("fresh client authenticated existing final release at sequence %d", stateView.Sequence)
		return
	}
	if stateView.Progress.ReleaseReview == nil {
		t.Fatal("live ceremony has no frozen release review")
	}
	releaseSigner, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		t.Fatal(err)
	}
	verify := exec.Command(proofBinary, "release", "verify", "--ceremony", inspector.CeremonyPath, "--ceremony-signature", inspector.CeremonySignaturePath, "--coordinator-public-key-file", coordinatorKey, "--keys-dir", packageDir, "--manifest-public-key-file", filepath.Join(packageDir, "manifest-public-key.hex"), "--signature-key-id", releaseSigner.Identity.KeyID)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("authenticate retained release package: %v: %s", err, output)
	}
	_, _, sourcePaths, err := workflowV4ReleaseFiles(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	releaseDir := filepath.Join(ceremonyRoot, "final", "release")
	if err := os.MkdirAll(releaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, source := range sourcePaths {
		target := filepath.Join(releaseDir, filepath.FromSlash(name))
		if err := copyLiveFileNewOrExact(source, target); err != nil {
			t.Fatalf("stage release file %q: %v", name, err)
		}
	}
	_, _, releasePaths, err := workflowV4ReleaseFiles(releaseDir)
	if err != nil {
		t.Fatal(err)
	}
	record, signature := releasePaths["manifest.json"], releasePaths["manifest.sig"]
	evidence, err := workflowV4FinalReleaseEvidence(releasePaths)
	if err != nil {
		t.Fatal(err)
	}
	basis := strings.TrimPrefix(snapshot.Head().Record.Digest.SHA256, "sha256:")[:16]
	outDir := filepath.Join(ceremonyRoot, "checkpoints", "final", "release-"+basis)
	if err := os.MkdirAll(filepath.Dir(outDir), 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"checkpoint", "record-v4", "--ceremony", inspector.CeremonyPath, "--ceremony-signature", inspector.CeremonySignaturePath, "--coordinator-public-key-file", coordinatorKey, "--artifact-root", ceremonyRoot, "--checkpoint", filepath.Join(ceremonyRoot, filepath.FromSlash(snapshot.Head().Record.Name)), "--checkpoint-signature", filepath.Join(ceremonyRoot, filepath.FromSlash(snapshot.Head().Signature.Name)), "--transition", "final-release-recorded", "--record", record, "--record-signature", signature}
	for _, path := range evidence {
		args = append(args, "--evidence", path)
	}
	args = append(args, "--coordinator-signing-key", coordinatorSigningKey, "--out-dir", outDir)
	if output, err := exec.Command(proofBinary, args...).CombinedOutput(); err != nil {
		t.Fatalf("record final release checkpoint: %v: %s", err, output)
	}
	config.CeremonyPath = inspector.CeremonyPath
	config.CeremonySignature = inspector.CeremonySignaturePath
	config.CoordinatorPublicKey = coordinatorKey
	config.CeremonyBinary = proofBinary
	hostConfig := filepath.Join(workspace, "storage.json")
	if err := writeJSONNoReplace(hostConfig, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	if err := runCoordinatorCommitV4([]string{"--storage", hostConfig, "--artifact-root", ceremonyRoot, "--checkpoint", filepath.Join(outDir, "checkpoint.json"), "--checkpoint-signature", filepath.Join(outDir, "checkpoint.sig"), "--ceremony", inspector.CeremonyPath, "--ceremony-signature", inspector.CeremonySignaturePath, "--coordinator-key", coordinatorKey, "--ceremony-binary", proofBinary}); err != nil {
		t.Fatal(err)
	}
	completed := sync("after")
	completedState, err := completed.State()
	if err != nil {
		t.Fatal(err)
	}
	if completedState.Sequence != stateView.Sequence+1 || completedState.Progress.FinalRelease == nil || completedState.Transition.Kind != "final-release-recorded" {
		t.Fatalf("fresh client did not reconstruct terminal release state: sequence=%d transition=%s", completedState.Sequence, completedState.Transition.Kind)
	}
	t.Logf("fresh client authenticated terminal release checkpoint at sequence %d", completedState.Sequence)
}

func copyLiveFileNewOrExact(source, target string) error {
	if existing, err := workflowV4LocalRef(filepath.Base(target), target); err == nil {
		want, err := workflowV4LocalRef(filepath.Base(source), source)
		if err != nil {
			return err
		}
		if existing.Digest != want.Digest {
			return errors.New("existing destination differs")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.Join(copyErr, closeErr)
	}
	return nil
}
