package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type workflowV4LiveRole struct {
	profile     guidedProfile
	signer      guidedProfile
	identity    setupIdentity
	inspector   transcript.Inspector
	journal     *workflowV4Journal
	participant *access.RoleConfig
}

// TestV4LiveFullR2Journey is opt-in because it creates a uniquely identified
// two-phase rehearsal in the configured test buckets and waits for two real
// future Quicknet rounds. It drives the same role action functions as the
// normal coordinator, participant and release-signer guide.
func TestV4LiveFullR2Journey(t *testing.T) { runLiveFullProviderJourney(t, false) }
func TestV4LiveFullAWSJourney(t *testing.T) {
	if os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("requires dedicated AWS test approval")
	}
	runLiveFullProviderJourney(t, true)
}

// Tests may switch the actual native application at an explicit completed-turn
// boundary. This hook is compiled only into tests, never into released Relay.
type workflowV4LiveUpgradeHook struct {
	LocalStorage       bool
	Source             string
	Candidate          string
	TargetWork         string
	AfterPhase1        func(*workflowV4LiveRole)
	OldCalls, NewCalls int
}

func runV4LiveFullR2Journey(t *testing.T, upgradeHook *workflowV4LiveUpgradeHook) {
	runLiveFullProviderJourneyWithUpgrade(t, false, upgradeHook)
}
func runLiveFullProviderJourney(t *testing.T, awsLive bool) {
	runLiveFullProviderJourneyWithUpgrade(t, awsLive, nil)
}
func runLiveFullProviderJourneyWithUpgrade(t *testing.T, awsLive bool, upgradeHook *workflowV4LiveUpgradeHook) {
	offlineImage := os.Getenv("RELAY_PREPARE_TEST_IMAGE")
	onlineImage := os.Getenv("RELAY_V4_LIVE_ONLINE_IMAGE")
	relayBinary := os.Getenv("RELAY_V4_LIVE_RELAY_BINARY")
	configPath := os.Getenv("RELAY_V4_LIVE_R2_CONFIG")
	credentialsPath := os.Getenv("RELAY_V4_LIVE_R2_CREDENTIALS")
	parentPath := os.Getenv("RELAY_V4_LIVE_R2_PARENT")
	controlPath := os.Getenv("RELAY_V4_LIVE_R2_CONTROL")
	awsLane := os.Getenv("RELAY_UPGRADE_LIVE_PROVIDER") == "aws"
	if awsLane {
		if upgradeHook == nil || os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
			t.Fatal("AWS upgrade lane requires explicit test approval and an upgrade hook")
		}
		configPath = os.Getenv("RELAY_V4_LIVE_AWS_CONFIG")
		credentialsPath = os.Getenv("RELAY_AWS_LIVE_CREDENTIALS_FILE")
		parentPath, controlPath = "", ""
	}
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	if awsLive {
		configPath = os.Getenv("RELAY_AWS_LIVE_SETTINGS_FILE")
		parentPath, controlPath = "", ""
	}
	if offlineImage == "" || onlineImage == "" || relayBinary == "" || configPath == "" || (!awsLive && credentialsPath == "") || (!awsLive && !awsLane && (parentPath == "" || controlPath == "")) || proofBinary == "" {
		t.Skip("set the V4 live images, provider settings and credentials, and native Relay and proof-tool binaries")
	}
	if awsLive {
		credentialsPath = freshAWSLiveCredentials(t)
	}
	// Live development runs may start from locally named images. Resolve those
	// names once and pass only immutable image IDs to every ceremony command.
	// This retains the production rejection of mutable tags while preventing a
	// long rehearsal from depending on a tag that can move during the run.
	offlineImage = workflowV4LiveImmutableImage(t, offlineImage)
	onlineImage = workflowV4LiveImmutableImage(t, onlineImage)
	for _, path := range []string{relayBinary, configPath, credentialsPath, parentPath, controlPath, proofBinary} {
		if (awsLive || awsLane) && path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("live test paths must be absolute and clean")
		}
	}
	previousExecutor := workflowV4ChildExecutor
	workflowV4ChildExecutor = func(args []string) error {
		args = append([]string(nil), args...)
		if awsLive {
			for n, a := range args {
				if a == "--aws-credentials" && n+1 < len(args) {
					args[n+1] = freshAWSLiveCredentials(t)
				}
			}
		}
		binary := relayBinary
		if upgradeHook != nil {
			binary = upgradeHook.Source
			for n, arg := range args {
				if arg == "--work" && n+1 < len(args) && upgradeHook.TargetWork != "" && args[n+1] == upgradeHook.TargetWork {
					binary = upgradeHook.Candidate
				}
			}
			if binary == upgradeHook.Source {
				upgradeHook.OldCalls++
			} else {
				upgradeHook.NewCalls++
			}
		}
		command := exec.Command(binary, args...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		return command.Run()
	}
	t.Cleanup(func() { workflowV4ChildExecutor = previousExecutor })
	var base access.StorageConfig
	var err error
	if awsLive {
		var settings coordinatorStorageSettings
		if err = setupReadJSON(configPath, &settings); err != nil {
			t.Fatal(err)
		}
		base, err = settings.infrastructure()
		if err != nil {
			t.Fatal(err)
		}
		requireAWSLiveConfiguration(t, base)
	} else {
		rawConfig, e := os.ReadFile(configPath)
		if e != nil {
			t.Fatal(e)
		}
		base, err = access.Decode(rawConfig, access.StorageConfig.Validate)
		if err != nil || (!awsLane && base.Provider != "r2") {
			t.Fatalf("valid R2 config required: %v", err)
		}
		if awsLane {
			requireAWSLiveConfiguration(t, base)
		}
	}
	platform, err := machineDockerPlatform()
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("RELAY_V4_LIVE_WORK_ROOT")
	if root == "" {
		root = t.TempDir()
	} else {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			t.Fatal("live retained work root must be an absolute clean path")
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("live retained work root must be fresh: %v", err)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Logf("retaining live rehearsal workspace at %s", root)
	}
	settingsRoot := filepath.Join(root, "settings")
	if err := os.MkdirAll(settingsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	coordinator := newWorkflowV4LiveRole(t, root, "coordinator", "coordinator", onlineImage, offlineImage, platform)
	participant := newWorkflowV4LiveRole(t, root, "participant", "participant-01", offlineImage, offlineImage, platform)
	releaseSigner := newWorkflowV4LiveRole(t, root, "release-signer", "release-signer", offlineImage, offlineImage, platform)
	// Coordinator setup aliases are derived from the ceremony name. Give every
	// live run a fresh name so an old developer profile can never substitute a
	// previously saved command for this run.
	nameHash := sha256.Sum256([]byte(root))
	coordinator.profile.Name = fmt.Sprintf("v4-live-coordinator-%x", nameHash[:6])
	coordinator.signer.Name = offlineRoleAlias(coordinator.profile.Name, "coordinator")
	coordinator.profile.Credentials = credentialsPath
	coordinator.profile.R2Parent = parentPath
	coordinator.profile.R2Control = controlPath

	w := setupFixture(t)
	w.d.Name = coordinator.profile.Name
	w.d.Work, w.d.Trust, w.d.Keys = coordinator.profile.Work, coordinator.profile.Trust, coordinator.profile.Keys
	w.d.Identities = setupRoster{
		Coordinator:   coordinator.identity,
		ReleaseSigner: releaseSigner.identity,
		Roster:        []setupParticipant{{Identity: participant.identity}},
	}
	w.d.Policy.Assurance = &setupAssurance{}
	w.d.Policy.Phase1 = setupPhase{Participants: []string{participant.identity.ID}, Minimum: 1}
	w.d.Policy.Phase2 = setupPhase{Participants: []string{participant.identity.ID}, Minimum: 1}
	w.d.Policy.Beacon.Lead = 1
	digest, err := setupFileHash(proofBinary)
	if err != nil {
		t.Fatal(err)
	}
	w.d.Binaries = []setupBinary{{Path: proofBinary, SHA256: digest}}
	if upgradeHook != nil {
		// Upgrade lanes authenticate the running Linux binary itself. Do not
		// add that same platform twice as a supposed host-inspector companion.
		w.d.Binaries = nil
		w.d.ArchitecturePolicy = "single"
	}
	w.draftPath = filepath.Join(w.d.Work, "coordinator-setup", "draft.json")
	if err := os.MkdirAll(filepath.Dir(w.draftPath), 0o700); err != nil {
		t.Fatal(err)
	}
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	w.output = new(bytes.Buffer)
	w.run = workflowV4LiveSetupRunner(t, offlineImage, platform, w.d)
	if err := w.initialize(); err != nil {
		t.Fatal(err)
	}
	copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), filepath.Join(coordinator.profile.Trust, "coordinator-public-key.hex"))

	ceremonyRoot := filepath.Join(coordinator.profile.Work, "ceremony", "public")
	hostInspector := transcript.Inspector{
		Executable: proofBinary, CeremonyPath: filepath.Join(ceremonyRoot, "ceremony.json"), CeremonySignaturePath: filepath.Join(ceremonyRoot, "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), TranscriptRoot: ceremonyRoot,
	}
	if upgradeHook != nil {
		driver := dockerDriver{image: offlineImage, platform: platform, ceremonyBinary: dockerCeremonyBinary, root: ceremonyRoot, inspectionRoot: coordinator.profile.Work, definition: hostInspector.CeremonyPath, definitionSig: hostInspector.CeremonySignaturePath, coordinatorKey: hostInspector.CoordinatorPublicKeyPath, client: osDockerCommandClient{binary: workflowV4LiveDockerCLI(t)}}
		hostInspector = driver.inspector()
	}
	protocol, err := hostInspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	config := base
	config.Schema = access.StorageConfigSchema
	config.CeremonyID = protocol.Definition.CeremonyID
	config.CeremonyPath = "/work/ceremony/public/ceremony.json"
	config.CeremonySignature = "/work/ceremony/public/ceremony.sig"
	config.CoordinatorPublicKey = "/trust/setup-coordinator.hex"
	config.CeremonyBinary = "/usr/local/bin/mpc-ceremony"
	writeWorkflowV4LiveConfig(t, coordinator.profile.Work, config)
	if err := runWorkflowV4ProfileCommand(coordinator.profile, []string{
		"relay", "coordinator", "commit-v4", "--storage", "/work/ceremony/config/relay-storage.json", "--artifact-root", "/work/ceremony/public",
		"--checkpoint", "/work/ceremony/public/checkpoints/initial/checkpoint.json", "--checkpoint-signature", "/work/ceremony/public/checkpoints/initial/checkpoint.sig",
		"--ceremony", config.CeremonyPath, "--ceremony-signature", config.CeremonySignature, "--coordinator-key", config.CoordinatorPublicKey, "--ceremony-binary", config.CeremonyBinary,
	}, true); err != nil {
		t.Fatal(err)
	}

	for _, role := range []*workflowV4LiveRole{&coordinator, &participant, &releaseSigner} {
		prepareWorkflowV4LiveRole(t, role, coordinator, config, protocol, offlineImage, platform)
		defer role.journal.close()
	}
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}
	prepareWorkflowV4LiveEnrollment(t, coordinator)
	prepareWorkflowV4LiveEnrollment(t, participant)
	prepareWorkflowV4LiveEnrollment(t, releaseSigner)

	roles := map[string]*workflowV4LiveRole{
		coordinator.identity.ID:   &coordinator,
		participant.identity.ID:   &participant,
		releaseSigner.identity.ID: &releaseSigner,
	}
	for {
		snapshot := syncWorkflowV4LiveRole(t, &coordinator, objects)
		expected, err := workflowV4NextRequiredEnrollment(snapshot, protocol)
		if err != nil {
			t.Fatal(err)
		}
		if expected == nil {
			break
		}
		progress, err := workflowV4CoordinatorEnrollmentProgressFor(snapshot, protocol, *expected, coordinator.journal.state.Marker.Binding, config, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if expected.Role == "coordinator" {
			ui := workflowV4LiveUI("RECORD COORDINATOR ENROLLMENT\n")
			if err := runWorkflowV4CoordinatorExpectedEnrollment(ui, snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, *expected, progress); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if expected.Role == "release-signer" {
			// Transfer public enrollment only; the signer never gets an upload grant.
			source := filepath.Join(releaseSigner.profile.Work, "my-enrollment")
			ui := workflowV4LiveUI("I\n" + source + "\nVERIFY AND RECORD ENROLLMENT\nQ\n")
			if err := runWorkflowV4GuideLoop(coordinator.profile, coordinator.signer, coordinator.identity, protocol, coordinator.journal, config, coordinator.inspector, workflowV4LiveDockerCLI(t), nil, ui, func() (storagefirst.SnapshotV4, error) {
				return coordinator.journal.syncV4(objects, coordinator.inspector, workflowV4LiveDockerCLI(t))
			}); err != nil {
				t.Fatal(err)
			}
			updated := syncWorkflowV4LiveRole(t, &coordinator, objects)
			committed, err := workflowV4EnrollmentCommitted(updated, releaseSigner.identity.ID)
			if err != nil || !committed {
				t.Fatalf("offline enrollment handoff failed: %v: %s", err, ui.output)
			}
			continue
		}
		ui := workflowV4LiveUI("CREATE ENROLLMENT GRANT\n")
		if err := runWorkflowV4CoordinatorExpectedEnrollment(ui, snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, *expected, progress); err != nil {
			t.Fatal(err)
		}
		progress, err = workflowV4CoordinatorEnrollmentProgressFor(snapshot, protocol, *expected, coordinator.journal.state.Marker.Binding, config, time.Now().UTC())
		if err != nil || progress.EnrollmentGrant == nil {
			t.Fatalf("missing enrollment grant: %+v %v", progress, err)
		}
		owner := roles[expected.Identity.ID]
		ownerSnapshot := syncWorkflowV4LiveRole(t, owner, objects)
		ui = workflowV4LiveUI(progress.EnrollmentGrantPath + "\nUPLOAD ENROLLMENT\n")
		if err := runWorkflowV4OwnEnrollmentUpload(ui, ownerSnapshot, protocol, owner.profile, config, owner.inspector, owner.identity); err != nil {
			t.Fatal(err)
		}
		ui = workflowV4LiveUI("CHECK ENROLLMENT INBOX\n")
		if err := runWorkflowV4CoordinatorExpectedEnrollment(ui, snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, *expected, progress); err != nil {
			t.Fatal(err)
		}
		progress, err = workflowV4CoordinatorEnrollmentProgressFor(snapshot, protocol, *expected, coordinator.journal.state.Marker.Binding, config, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		ui = workflowV4LiveUI("VERIFY AND RECORD ENROLLMENT\n")
		if err := runWorkflowV4CoordinatorExpectedEnrollment(ui, snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, *expected, progress); err != nil {
			t.Fatal(err)
		}
	}

	runWorkflowV4LiveTurn(t, objects, protocol, config, &coordinator, &participant, "phase1")
	if upgradeHook != nil {
		// A normal reopened CLI refreshes its accepted-state anchor before exit.
		// Local TLS fixtures skip that terminal, so perform the same verified sync.
		syncWorkflowV4LiveRole(t, &coordinator, objects)
		upgradeHook.AfterPhase1(&coordinator)
	}
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4ClosePhase1, "CLOSE PHASE1\n")
	runWorkflowV4LiveBeacon(t, objects, protocol, &coordinator, workflowV4BeaconPhase1, "RECORD PHASE1 BEACON\n")
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4SealPhase1, "SEAL PHASE1\n")
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4StartPhase2, "START PHASE2\n")
	runWorkflowV4LiveTurn(t, objects, protocol, config, &coordinator, &participant, "phase2")
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4ClosePhase2, "CLOSE PHASE2\n")
	runWorkflowV4LiveBeacon(t, objects, protocol, &coordinator, workflowV4BeaconPhase2, "RECORD PHASE2 BEACON\n")
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4Finalize, "FINALIZE CANDIDATE\n")
	runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, workflowV4Review, "SIGN EVIDENCE BUNDLE\n")

	snapshot := syncWorkflowV4LiveRole(t, &coordinator, objects)
	if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI("CREATE RELEASE GRANT\n"), workflowV4Release, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
		t.Fatal(err)
	}
	grant, grantPath, err := workflowV4CurrentReleaseGrant(snapshot, protocol, config, coordinator.profile.Work, releaseSigner.identity.ID, time.Now().UTC())
	if err != nil || grant == nil {
		t.Fatalf("missing release grant: %v", err)
	}
	completeWorkflowV4LiveRelease(t, objects, protocol, config, root, &coordinator, &releaseSigner, grantPath)
}

func completeWorkflowV4LiveRelease(t *testing.T, objects store.Client, protocol transcript.DefinitionProtocol, config access.StorageConfig, root string, coordinator, releaseSigner *workflowV4LiveRole, grantPath string) {
	t.Helper()
	// Exercise the coordinator's public export and the signer's offline import.
	exported := filepath.Join(coordinator.profile.Work, fmt.Sprintf("offline-review-snapshot-%d", time.Now().UnixNano()))
	ui := workflowV4LiveUI("E\n" + exported + "\nQ\n")
	if err := runWorkflowV4GuideLoop(coordinator.profile, coordinator.signer, coordinator.identity, protocol, coordinator.journal, config, coordinator.inspector, workflowV4LiveDockerCLI(t), nil, ui, func() (storagefirst.SnapshotV4, error) {
		return coordinator.journal.syncV4(objects, coordinator.inspector, workflowV4LiveDockerCLI(t))
	}); err != nil {
		t.Fatal(err)
	}
	offlineObjects, err := openWorkflowV4OfflineStore(exported)
	if err != nil {
		t.Fatal(err)
	}
	ui = workflowV4LiveUI("1\nSIGN RELEASE PACKAGE\nQ\n")
	if err := runWorkflowV4GuideLoop(releaseSigner.profile, releaseSigner.signer, releaseSigner.identity, protocol, releaseSigner.journal, access.StorageConfig{}, releaseSigner.inspector, workflowV4LiveDockerCLI(t), nil, ui, func() (storagefirst.SnapshotV4, error) {
		return releaseSigner.journal.syncV4(offlineObjects, releaseSigner.inspector, workflowV4LiveDockerCLI(t))
	}); err != nil {
		t.Fatal(err)
	}
	progress, err := workflowV4ReleaseSignerProgressFor(releaseSigner.profile.Work)
	if err != nil || !progress.PackageReady {
		t.Fatalf("offline signing failed: %v: %s", err, ui.output)
	}
	returned := filepath.Join(coordinator.profile.Work, fmt.Sprintf("returned-release-package-%d", time.Now().UnixNano()))
	if err := os.CopyFS(returned, os.DirFS(progress.PackageDir)); err != nil {
		t.Fatal(err)
	}
	ui = workflowV4LiveUI("U\n" + returned + "\n" + grantPath + "\nUPLOAD RELEASE PACKAGE\nQ\n")
	if err := runWorkflowV4GuideLoop(coordinator.profile, coordinator.signer, coordinator.identity, protocol, coordinator.journal, config, coordinator.inspector, workflowV4LiveDockerCLI(t), nil, ui, func() (storagefirst.SnapshotV4, error) {
		return coordinator.journal.syncV4(objects, coordinator.inspector, workflowV4LiveDockerCLI(t))
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := syncWorkflowV4LiveRole(t, coordinator, objects)
	if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI("CHECK RELEASE INBOX\nVERIFY AND RECORD RELEASE\n"), workflowV4Release, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
		t.Fatal(err)
	}

	freshRoot := filepath.Join(root, fmt.Sprintf("fresh-client-%d", time.Now().UnixNano()))
	freshTranscript := filepath.Join(freshRoot, "ceremony", "public")
	freshTrust := filepath.Join(freshRoot, "trust")
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Work, "ceremony", "public", name), filepath.Join(freshTranscript, name))
	}
	copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), filepath.Join(freshTrust, "coordinator-public-key.hex"))
	freshInspector := workflowV4LiveFreshInspector(t, coordinator.profile, freshRoot, freshTranscript, freshTrust)
	highWater, err := state.OpenWorkspaceHighWater(filepath.Join(freshRoot, "high-water"), protocol.Definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := storagefirst.SyncV4(objects, freshInspector, highWater, protocol.Definition.CeremonyID, freshRoot)
	if err != nil {
		t.Fatal(err)
	}
	stateView, err := terminal.State()
	if err != nil || stateView.Progress.FinalRelease == nil {
		t.Fatalf("fresh verifier did not reconstruct the final release: %+v %v", stateView.Progress, err)
	}
	lane := "live R2"
	if awsLane {
		lane = "live AWS S3"
	}
	if upgradeHook != nil && upgradeHook.LocalStorage {
		lane = "local storage adapter (not provider validation)"
	}
	t.Logf("completed and freshly reconstructed %s V4 ceremony %s at signed update %d", lane, protocol.Definition.CeremonyID, stateView.Sequence)
	if upgradeHook != nil && (upgradeHook.OldCalls == 0 || upgradeHook.NewCalls == 0) {
		t.Fatal("both actual application versions must execute ceremony commands")
	}
}

func workflowV4LiveImmutableImage(t *testing.T, image string) string {
	t.Helper()
	id, resolved, err := workflowV4LiveImmutableImageWithRunner(image, func(name string) ([]byte, error) {
		return exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", name).CombinedOutput()
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved {
		t.Logf("resolved local live-test image %q to immutable %s", image, id)
	}
	return id
}

func workflowV4LiveImmutableImageWithRunner(image string, inspect func(string) ([]byte, error)) (string, bool, error) {
	valid := func(value string) bool {
		if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
			return false
		}
		_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
		return err == nil
	}
	if valid(image) {
		return image, false, nil
	}
	pinned := roleImagePattern.MatchString(image) && strings.Contains(image, "@sha256:")
	output, err := inspect(image)
	if err != nil {
		return "", false, fmt.Errorf("resolve live-test image %q to its immutable local ID: %w: %s", image, err, output)
	}
	id := strings.TrimSpace(string(output))
	if !valid(id) {
		return "", false, fmt.Errorf("docker returned an invalid immutable image ID for %q", image)
	}
	if pinned {
		return image, false, nil
	}
	return id, true, nil
}

func TestWorkflowV4LiveImageTagsResolveOnceToImmutableIDs(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	calls := 0
	got, resolved, err := workflowV4LiveImmutableImageWithRunner("local-live:arm64", func(name string) ([]byte, error) {
		calls++
		if name != "local-live:arm64" {
			t.Fatalf("inspected image %q", name)
		}
		return []byte(id + "\n"), nil
	})
	if err != nil || !resolved || got != id || calls != 1 {
		t.Fatalf("tag resolution = (%q, %t, %v, calls=%d)", got, resolved, err, calls)
	}
	got, resolved, err = workflowV4LiveImmutableImageWithRunner(id, func(string) ([]byte, error) {
		t.Fatal("immutable ID must not be resolved again")
		return nil, nil
	})
	if err != nil || resolved || got != id {
		t.Fatalf("immutable input = (%q, %t, %v)", got, resolved, err)
	}
}

// TestV4LiveResumeR2Release is an opt-in recovery check for a live journey
// that already reached the frozen release review. It intentionally reopens the
// original journals and runtimes rather than inventing replacement profiles,
// then finishes release signing/upload, coordinator acceptance, and a fresh
// public reconstruction. This keeps late integration failures from forcing a
// new ceremony merely to exercise the remaining release boundary.
func TestV4LiveResumeR2Release(t *testing.T) {
	root := os.Getenv("RELAY_V4_LIVE_RESUME_ROOT")
	relayBinary := os.Getenv("RELAY_V4_LIVE_RELAY_BINARY")
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	credentialsPath := os.Getenv("RELAY_V4_LIVE_R2_CREDENTIALS")
	parentPath := os.Getenv("RELAY_V4_LIVE_R2_PARENT")
	controlPath := os.Getenv("RELAY_V4_LIVE_R2_CONTROL")
	if root == "" || relayBinary == "" || proofBinary == "" || credentialsPath == "" || parentPath == "" || controlPath == "" {
		t.Skip("set the retained V4 live root, Relay/proof-tool binaries, and three R2 credential paths")
	}
	for _, path := range []string{root, relayBinary, proofBinary, credentialsPath, parentPath, controlPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("live recovery paths must be absolute and clean")
		}
	}
	previousExecutor := workflowV4ChildExecutor
	workflowV4ChildExecutor = func(args []string) error {
		command := exec.Command(relayBinary, args...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		return command.Run()
	}
	t.Cleanup(func() { workflowV4ChildExecutor = previousExecutor })

	coordinatorRoot := filepath.Join(root, "coordinator")
	ceremonyRoot := filepath.Join(coordinatorRoot, "work", "ceremony", "public")
	hostInspector := transcript.Inspector{
		Executable:               proofBinary,
		CeremonyPath:             filepath.Join(ceremonyRoot, "ceremony.json"),
		CeremonySignaturePath:    filepath.Join(ceremonyRoot, "ceremony.sig"),
		CoordinatorPublicKeyPath: filepath.Join(coordinatorRoot, "trust", "setup-coordinator.hex"),
		TranscriptRoot:           ceremonyRoot,
	}
	protocol, err := hostInspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(coordinatorRoot, "work", "ceremony", "config", "relay-storage.json")
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := access.Decode(rawConfig, access.StorageConfig.Validate)
	if err != nil || config.Provider != "r2" || config.CeremonyID != protocol.Definition.CeremonyID {
		t.Fatalf("retained recovery requires its exact R2 ceremony configuration: %v", err)
	}
	coordinator := reopenWorkflowV4LiveRole(t, root, "coordinator", protocol)
	coordinator.profile.Credentials = credentialsPath
	coordinator.profile.R2Parent = parentPath
	coordinator.profile.R2Control = controlPath
	releaseSigner := reopenWorkflowV4LiveRole(t, root, "release-signer", protocol)
	defer coordinator.journal.close()
	defer releaseSigner.journal.close()
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}

	releaseSnapshot := syncWorkflowV4LiveRole(t, &releaseSigner, objects)
	progress, err := workflowV4ReleaseSignerProgressFor(releaseSigner.profile.Work)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.PackageReady {
		if err := runWorkflowV4ReleaseSignerAction(workflowV4LiveUI("SIGN RELEASE PACKAGE\n"), releaseSnapshot, protocol, config, releaseSigner.profile, releaseSigner.signer, releaseSigner.identity, progress); err != nil {
			t.Fatal(err)
		}
		progress, err = workflowV4ReleaseSignerProgressFor(releaseSigner.profile.Work)
		if err != nil || !progress.PackageReady {
			t.Fatalf("release package was not retained after signing: %+v %v", progress, err)
		}
	}
	coordinatorSnapshot := syncWorkflowV4LiveRole(t, &coordinator, objects)
	coordinatorState, err := coordinatorSnapshot.State()
	if err != nil {
		t.Fatal(err)
	}
	if coordinatorState.Progress.FinalRelease == nil {
		grant, grantPath, err := workflowV4CurrentReleaseGrant(coordinatorSnapshot, protocol, config, coordinator.profile.Work, releaseSigner.identity.ID, time.Now().UTC())
		if err != nil || grant == nil || grantPath == "" {
			t.Fatalf("retained release grant is unavailable: %v", err)
		}
		received := filepath.Join(coordinator.profile.Work, "workflow-v4", "coordinator", "release", "received", grant.AttemptID)
		if _, err := os.Lstat(received); errors.Is(err, os.ErrNotExist) {
			if err := runWorkflowV4ReleaseSignerAction(workflowV4LiveUI(grantPath+"\nUPLOAD RELEASE PACKAGE\n"), releaseSnapshot, protocol, config, releaseSigner.profile, releaseSigner.signer, releaseSigner.identity, progress); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		coordinatorSnapshot = syncWorkflowV4LiveRole(t, &coordinator, objects)
		input := "CHECK RELEASE INBOX\nVERIFY AND RECORD RELEASE\n"
		if _, err := os.Lstat(received); err == nil {
			input = "VERIFY AND RECORD RELEASE\n"
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI(input), workflowV4Release, coordinatorSnapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
			t.Fatal(err)
		}
	}

	freshRoot := t.TempDir()
	freshTranscript := filepath.Join(freshRoot, "ceremony", "public")
	freshTrust := filepath.Join(freshRoot, "trust")
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		copyWorkflowV4LiveFile(t, filepath.Join(ceremonyRoot, name), filepath.Join(freshTranscript, name))
	}
	copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), filepath.Join(freshTrust, "coordinator-public-key.hex"))
	freshInspector := workflowV4LiveFreshInspector(t, coordinator.profile, freshRoot, freshTranscript, freshTrust)
	highWater, err := state.OpenWorkspaceHighWater(filepath.Join(freshRoot, "high-water"), protocol.Definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := storagefirst.SyncV4(objects, freshInspector, highWater, protocol.Definition.CeremonyID, freshRoot)
	if err != nil {
		t.Fatal(err)
	}
	stateView, err := terminal.State()
	if err != nil || stateView.Progress.FinalRelease == nil {
		t.Fatalf("fresh verifier did not reconstruct the resumed final release: %+v %v", stateView.Progress, err)
	}
	t.Logf("resumed and freshly reconstructed live R2 V4 ceremony %s at signed update %d", protocol.Definition.CeremonyID, stateView.Sequence)
}

func workflowV4LiveFreshInspector(t *testing.T, profile guidedProfile, freshRoot, transcriptRoot, trustRoot string) transcript.Inspector {
	t.Helper()
	driver := dockerDriver{
		image: profile.Image, platform: profile.Platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony",
		root: transcriptRoot, inspectionRoot: freshRoot,
		definition: filepath.Join(transcriptRoot, "ceremony.json"), definitionSig: filepath.Join(transcriptRoot, "ceremony.sig"),
		coordinatorKey: filepath.Join(trustRoot, "coordinator-public-key.hex"),
		client:         osDockerCommandClient{binary: workflowV4LiveDockerCLI(t)},
	}
	return driver.inspector()
}

func reopenWorkflowV4LiveRole(t *testing.T, root, role string, protocol transcript.DefinitionProtocol) workflowV4LiveRole {
	t.Helper()
	base := filepath.Join(root, role)
	work, trust, keys := filepath.Join(base, "work"), filepath.Join(base, "trust"), filepath.Join(base, "keys")
	var marker workflowV4Marker
	if err := readWorkflowV4JSON(filepath.Join(work, ".relay-workspace-v4.json"), &marker); err != nil {
		t.Fatal(err)
	}
	var identity setupIdentity
	if err := readWorkflowV4JSON(filepath.Join(keys, "identity.json"), &identity); err != nil {
		t.Fatal(err)
	}
	online, okOnline := marker.Binding.Runtimes["online"]
	signing, okSigning := marker.Binding.Runtimes["signer"]
	if !okOnline || !okSigning || marker.Binding.Work != work || marker.Binding.Role != role || marker.Binding.IdentityID != identity.ID {
		t.Fatal("retained V4 role binding is incomplete or belongs to another workspace")
	}
	profile := guidedProfile{Schema: guidedSchema, Name: marker.Binding.Name, Role: role, Image: online.Image, Platform: online.Platform, Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Schema: guidedSchema, Name: offlineRoleAlias(profile.Name, role), Role: "decision-signer", Image: signing.Image, Platform: signing.Platform, Work: work, Trust: trust, Keys: keys}
	keyName := "coordinator-public-key.hex"
	if role == "coordinator" {
		keyName = "setup-coordinator.hex"
	}
	rootPath := filepath.Join(work, "ceremony", "public")
	driver := dockerDriver{image: profile.Image, platform: profile.Platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: rootPath, inspectionRoot: work, definition: filepath.Join(rootPath, "ceremony.json"), definitionSig: filepath.Join(rootPath, "ceremony.sig"), coordinatorKey: filepath.Join(trust, keyName), client: osDockerCommandClient{binary: workflowV4LiveDockerCLI(t)}}
	journal, err := openWorkflowV4Journal(protocol, protocol.DefinitionRefs, marker.Binding)
	if err != nil {
		t.Fatal(err)
	}
	return workflowV4LiveRole{profile: profile, signer: signer, identity: identity, inspector: driver.inspector(), journal: journal}
}

func newWorkflowV4LiveRole(t *testing.T, root, role, id, onlineImage, offlineImage, platform string) workflowV4LiveRole {
	t.Helper()
	base := filepath.Join(root, role)
	work, trust, keys := filepath.Join(base, "work"), filepath.Join(base, "trust"), filepath.Join(base, "keys")
	for _, dir := range []string{work, trust, keys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(pub)
	identity := setupIdentity{ID: id, DisplayName: "Live rehearsal " + role, KeyID: id + "-key", PublicKey: hex.EncodeToString(pub), Fingerprint: fmt.Sprintf("sha256:%x", fingerprint)}
	if err := writeJSONNoReplace(filepath.Join(keys, "identity.json"), identity, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "signing.hex"), []byte(hex.EncodeToString(private.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "v4-live-" + role
	profile := guidedProfile{Schema: guidedSchema, Name: name, Role: role, Image: onlineImage, Platform: platform, Work: work, Trust: trust, Keys: keys}
	signer := guidedProfile{Schema: guidedSchema, Name: offlineRoleAlias(name, role), Role: "decision-signer", Image: offlineImage, Platform: platform, Work: work, Trust: trust, Keys: keys}
	return workflowV4LiveRole{profile: profile, signer: signer, identity: identity}
}

func workflowV4LiveSetupRunner(t *testing.T, image, platform string, draft coordinatorDraft) func([]string) error {
	t.Helper()
	var command []string
	return func(args []string) error {
		if len(args) > 1 && args[1] == "setup" {
			for n, value := range args {
				if value == "--" {
					command = append([]string(nil), args[n+1:]...)
					return nil
				}
			}
			return errors.New("missing tool command")
		}
		if len(command) == 0 {
			return errors.New("missing tool command")
		}
		argv, err := dockerRoleArgs(dockerRoleOptions{role: "coordinator", image: image, platform: platform, work: draft.Work, trust: draft.Trust, keys: draft.Keys}, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		output, err := execDocker(argv)
		if err != nil {
			return fmt.Errorf("%w: %s", err, output)
		}
		return nil
	}
}

func execDocker(args []string) ([]byte, error) {
	return exec.Command("docker", args...).CombinedOutput()
}

func writeWorkflowV4LiveConfig(t *testing.T, work string, config access.StorageConfig) {
	t.Helper()
	path := filepath.Join(work, "ceremony", "config", "relay-storage.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyWorkflowV4LiveFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyWorkflowV4LiveBootstrap(t *testing.T, coordinator workflowV4LiveRole, role *workflowV4LiveRole, config access.StorageConfig) {
	t.Helper()
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Work, "ceremony", "public", name), filepath.Join(role.profile.Work, "ceremony", "public", name))
	}
	copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), filepath.Join(role.profile.Trust, "coordinator-public-key.hex"))
	copyWorkflowV4LiveFile(t, filepath.Join(coordinator.profile.Trust, "setup-coordinator.hex"), filepath.Join(role.profile.Trust, "setup-coordinator.hex"))
	writeWorkflowV4LiveConfig(t, role.profile.Work, config)
}

func prepareWorkflowV4LiveRole(t *testing.T, role *workflowV4LiveRole, coordinator workflowV4LiveRole, config access.StorageConfig, protocol transcript.DefinitionProtocol, contributorImage, platform string) {
	t.Helper()
	if role.profile.Work != coordinator.profile.Work {
		copyWorkflowV4LiveBootstrap(t, coordinator, role, config)
	}
	root := filepath.Join(role.profile.Work, "ceremony", "public")
	keyName := "coordinator-public-key.hex"
	if role.profile.Role == "coordinator" {
		keyName = "setup-coordinator.hex"
	}
	dockerCLI := workflowV4LiveDockerCLI(t)
	driver := dockerDriver{image: role.profile.Image, platform: platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: root, inspectionRoot: role.profile.Work, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: filepath.Join(role.profile.Trust, keyName), client: osDockerCommandClient{binary: dockerCLI}}
	role.inspector = driver.inspector()
	if role.profile.Role == "participant" {
		environment := guidedEnvironment{"linux", strings.TrimPrefix(platform, "linux/"), "operating-system-csprng", true, true, true, true, true, true}
		environmentPath := filepath.Join(role.profile.Work, "environment.json")
		canonical, err := json.Marshal(environment)
		if err != nil {
			t.Fatal(err)
		}
		if err := writePublicTextOnce(environmentPath, string(canonical)); err != nil {
			t.Fatal(err)
		}
		participant := access.RoleConfig{Schema: access.RoleConfigSchema, Role: "participant", IdentityID: role.identity.ID, Phase: "phase1", CeremonyID: protocol.Definition.CeremonyID, CeremonyHome: filepath.Join(role.profile.Work, "ceremony"), Root: root, Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"), CoordinatorKey: filepath.Join(role.profile.Trust, "coordinator-public-key.hex"), CeremonyBinary: "/usr/local/bin/mpc-ceremony", SigningKey: filepath.Join(role.profile.Keys, "signing.hex"), Environment: environmentPath, RunRoot: filepath.Join(role.profile.Work, "ceremony", "run"), StorageConfig: filepath.Join(role.profile.Work, "ceremony", "config", "relay-storage.json"), PublishedBaseURL: config.PublishedBaseURL, PublishedBucket: config.PublishedBucket, ExecutionMode: dockerExecutionMode, DockerImage: contributorImage, DockerPlatform: platform, DockerCLI: dockerCLI}
		if err := participant.Validate(); err != nil {
			t.Fatal(err)
		}
		role.participant = &participant
		role.profile.Image = contributorImage
	}
	binding, err := workflowV4ProfileBinding(role.profile, role.signer, protocol, role.identity, role.participant)
	if err != nil {
		t.Fatal(err)
	}
	role.journal, err = openWorkflowV4Journal(protocol, protocol.DefinitionRefs, binding)
	if err != nil {
		t.Fatal(err)
	}
}

func prepareWorkflowV4LiveEnrollment(t *testing.T, role workflowV4LiveRole) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(role.profile.Work, "enrollment-disclosure.txt"), []byte("Automated same-host live rehearsal; no operator independence claim.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roleName := role.profile.Role
	prepare := []string{"mpc-ceremony", "ops", "prepare-enrollment", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator-public-key.hex", "--identity", "/keys/identity.json", "--role", roleName, "--role-index", "1", "--disclosure", "/work/enrollment-disclosure.txt", "--enrolled-at", time.Now().UTC().Format(time.RFC3339Nano), "--out-dir", "/work/my-enrollment"}
	if err := runWorkflowV4ProfileCommand(role.signer, prepare, false); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(role.profile.Work, "my-enrollment", "canonical.json")
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	sign := []string{"mpc-ceremony", "ops", "sign", "--record-type", "enrollment", "--record", "/work/my-enrollment/canonical.json", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator-public-key.hex", "--signing-key", "/keys/signing.hex", "--reviewed", "--reviewed-sha256", fmt.Sprintf("%x", sha256.Sum256(raw)), "--out", "/work/my-enrollment/enrollment.sig"}
	if err := runWorkflowV4ProfileCommand(role.signer, sign, false); err != nil {
		t.Fatal(err)
	}
}

func syncWorkflowV4LiveRole(t *testing.T, role *workflowV4LiveRole, objects store.Client) storagefirst.SnapshotV4 {
	t.Helper()
	snapshot, err := role.journal.syncV4(objects, role.inspector, workflowV4LiveDockerCLI(t))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func workflowV4LiveDockerCLI(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(path)
}

func workflowV4LiveUI(input string) *coordinatorWizard {
	return &coordinatorWizard{input: bufio.NewReader(strings.NewReader(input)), output: new(bytes.Buffer)}
}

func runWorkflowV4LiveTurn(t *testing.T, objects store.Client, protocol transcript.DefinitionProtocol, config access.StorageConfig, coordinator, participant *workflowV4LiveRole, phase string) {
	t.Helper()
	snapshot := syncWorkflowV4LiveRole(t, coordinator, objects)
	view, err := snapshot.TurnV4(protocol, phase, "")
	if err != nil {
		t.Fatal(err)
	}
	progress, err := workflowV4CoordinatorProgressFor(snapshot, protocol, view, coordinator.journal.state.Marker.Binding, config, coordinator.inspector, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recommendation, err := snapshot.RecommendTurnV4(protocol, phase, storagefirst.Coordinator, "", progress.Local, "", time.Now().UTC())
	if err != nil || (recommendation.Action != "allocate-candidate-attempt" && recommendation.Action != "allocate-replacement-attempt") {
		t.Fatalf("expected allocation, got %+v %v", recommendation, err)
	}
	if err := runWorkflowV4CoordinatorAction(workflowV4LiveUI("ALLOCATE TURN\n"), snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, recommendation, view, progress); err != nil {
		t.Fatal(err)
	}
	snapshot = syncWorkflowV4LiveRole(t, coordinator, objects)
	view, err = snapshot.TurnV4(protocol, phase, "")
	if err != nil {
		t.Fatal(err)
	}
	progress, err = workflowV4CoordinatorProgressFor(snapshot, protocol, view, coordinator.journal.state.Marker.Binding, config, coordinator.inspector, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recommendation, err = snapshot.RecommendTurnV4(protocol, phase, storagefirst.Coordinator, "", progress.Local, "", time.Now().UTC())
	if err != nil || recommendation.Action != "issue-candidate-grant" {
		t.Fatalf("expected grant, got %+v %v", recommendation, err)
	}
	if err := runWorkflowV4CoordinatorAction(workflowV4LiveUI("CREATE GRANT\n"), snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, recommendation, view, progress); err != nil {
		t.Fatal(err)
	}
	grantPath := progress.GrantPath

	// Drive the same refresh/action loop as the normal participant launcher.
	// Its saved Phase 1 profile must work for both phases without test mutation.
	dockerCLI := workflowV4LiveDockerCLI(t)
	ui := workflowV4LiveUI("1\nCONTRIBUTE\n1\nCLEANUP PRECAUTIONS CONFIRMED\n1\n" + grantPath + "\nUPLOAD CANDIDATE\nQ\n")
	if err := runWorkflowV4GuideLoop(participant.profile, participant.signer, participant.identity, protocol, participant.journal, config, participant.inspector, dockerCLI, participant.participant, ui, func() (storagefirst.SnapshotV4, error) {
		return participant.journal.syncV4(objects, participant.inspector, dockerCLI)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ui.output.(*bytes.Buffer).String(), "action stopped:") || strings.Contains(ui.output.(*bytes.Buffer).String(), "synchronization failed:") {
		t.Fatalf("participant guide failed before inbox check: %s", ui.output)
	}
	if participant.participant.Phase != "phase1" {
		t.Fatal("participant guide changed the saved phase profile")
	}
	participantProgress, err := participant.journal.participantProgressV4(view.Scope, dockerCLI)
	if err != nil || participantProgress.Upload == nil {
		// A menu may safely return after failed synchronization or an action.
		// Do not misreport the later missing-inbox lookup as the first failure.
		logPath := filepath.Join(participant.profile.Work, "diagnostics", "live-"+phase+"-menu.txt")
		if e := os.MkdirAll(filepath.Dir(logPath), 0700); e != nil {
			t.Fatal(e)
		}
		if output, ok := ui.output.(*bytes.Buffer); ok {
			if e := os.WriteFile(logPath, output.Bytes(), 0600); e != nil {
				t.Fatal(e)
			}
		}
		t.Fatalf("participant did not complete its upload; inspect private menu log %s (progress error: %v)", logPath, err)
	}

	progress, err = workflowV4CoordinatorProgressFor(snapshot, protocol, view, coordinator.journal.state.Marker.Binding, config, coordinator.inspector, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recommendation, err = snapshot.RecommendTurnV4(protocol, phase, storagefirst.Coordinator, "", progress.Local, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := runWorkflowV4CoordinatorAction(workflowV4LiveUI("CHECK INBOX\n"), snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, recommendation, view, progress); err != nil {
		t.Fatal(err)
	}
	progress, err = workflowV4CoordinatorProgressFor(snapshot, protocol, view, coordinator.journal.state.Marker.Binding, config, coordinator.inspector, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recommendation, err = snapshot.RecommendTurnV4(protocol, phase, storagefirst.Coordinator, "", progress.Local, progress.Local.CandidateReceivedAttemptID, time.Now().UTC())
	if err != nil || recommendation.Action != "verify-and-accept-candidate" {
		t.Fatalf("expected acceptance, got %+v %v", recommendation, err)
	}
	if err := runWorkflowV4CoordinatorAction(workflowV4LiveUI("VERIFY AND ACCEPT\n"), snapshot, protocol, config, coordinator.profile, coordinator.signer, coordinator.inspector, recommendation, view, progress); err != nil {
		t.Fatal(err)
	}
}

func runWorkflowV4LiveLifecycle(t *testing.T, objects store.Client, protocol transcript.DefinitionProtocol, coordinator *workflowV4LiveRole, expected, confirmation string) {
	t.Helper()
	snapshot := syncWorkflowV4LiveRole(t, coordinator, objects)
	stateView, err := snapshot.State()
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := snapshot.Commitments()
	if err != nil {
		t.Fatal(err)
	}
	action, _, err := workflowV4CoordinatorLifecycleAction(stateView, commitments, protocol)
	if err != nil || action != expected {
		t.Fatalf("expected lifecycle %s, got %s: %v", expected, action, err)
	}
	if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI(confirmation), action, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
		t.Fatal(err)
	}
}

func runWorkflowV4LiveBeacon(t *testing.T, objects store.Client, protocol transcript.DefinitionProtocol, coordinator *workflowV4LiveRole, expected, confirmation string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		snapshot := syncWorkflowV4LiveRole(t, coordinator, objects)
		stateView, err := snapshot.State()
		if err != nil {
			t.Fatal(err)
		}
		commitments, err := snapshot.Commitments()
		if err != nil {
			t.Fatal(err)
		}
		action, _, err := workflowV4CoordinatorLifecycleAction(stateView, commitments, protocol)
		if err != nil || action != expected {
			t.Fatalf("expected beacon lifecycle %s, got %s: %v", expected, action, err)
		}
		err = runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI(confirmation), action, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector)
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "not public yet") || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
}

// Resume the exact retained tiny AWS review after a late local handoff failure.
// No initialization or contribution phase is repeated and no binding is rewritten.
func TestV4LiveResumeAWSOfflineRelease(t *testing.T) {
	if os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("explicit dedicated AWS test approval required")
	}
	root := os.Getenv("RELAY_V4_LIVE_RESUME_ROOT")
	proofBinary := os.Getenv("RELAY_V4_LIVE_PROOF_BINARY")
	relayBinary := os.Getenv("RELAY_V4_LIVE_RELAY_BINARY")
	for _, p := range []string{root, proofBinary, relayBinary} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			t.Fatal("exact retained root and tool paths required")
		}
	}
	ceremonyRoot := filepath.Join(root, "coordinator/work/ceremony/public")
	inspector := transcript.Inspector{Executable: proofBinary, CeremonyPath: filepath.Join(ceremonyRoot, "ceremony.json"), CeremonySignaturePath: filepath.Join(ceremonyRoot, "ceremony.sig"), CoordinatorPublicKeyPath: filepath.Join(root, "coordinator/trust/setup-coordinator.hex"), TranscriptRoot: ceremonyRoot}
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Definition.Mode != "rehearsal" {
		t.Fatal("only a retained rehearsal may be resumed by this test")
	}
	config, err := loadStorageConfig(filepath.Join(root, "coordinator/work/ceremony/config/relay-storage.json"))
	if err != nil {
		t.Fatal(err)
	}
	requireAWSLiveConfiguration(t, config)
	previous := workflowV4ChildExecutor
	workflowV4ChildExecutor = func(args []string) error {
		args = append([]string(nil), args...)
		for n, a := range args {
			if a == "--aws-credentials" && n+1 < len(args) {
				args[n+1] = freshAWSLiveCredentials(t)
			}
		}
		command := exec.Command(relayBinary, args...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		return command.Run()
	}
	t.Cleanup(func() { workflowV4ChildExecutor = previous })
	coordinator := reopenWorkflowV4LiveRole(t, root, "coordinator", protocol)
	defer coordinator.journal.close()
	coordinator.profile.Credentials = freshAWSLiveCredentials(t)
	signer := reopenWorkflowV4LiveRole(t, root, "release-signer", protocol)
	defer signer.journal.close()
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}
	snapshot := syncWorkflowV4LiveRole(t, &coordinator, objects)
	view, err := snapshot.State()
	if err != nil || view.Progress.ReleaseReview == nil || view.Progress.FinalRelease != nil {
		t.Fatal("exact unfinished review required", err)
	}
	grant, path, err := workflowV4CurrentReleaseGrant(snapshot, protocol, config, coordinator.profile.Work, signer.identity.ID, time.Now().UTC())
	if err != nil || grant == nil {
		t.Fatal("retained release grant required", err)
	}
	completeWorkflowV4LiveRelease(t, objects, protocol, config, root, &coordinator, &signer, path)
}
