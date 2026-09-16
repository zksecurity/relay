package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
