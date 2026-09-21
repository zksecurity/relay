package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
)

// Resume only the post-contribution tail of an explicitly selected test run.
// This does not activate an update, allocate a turn, or generate randomness.
func TestUpgradeResumeAWSAfterPhase2(t *testing.T) {
	root := os.Getenv("RELAY_UPGRADE_AWS_RESUME_ROOT")
	if root == "" || os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("requires retained AWS test root and explicit live approval")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("resume root must be absolute and clean")
	}
	f := realUpgradeFixture(t)
	work := filepath.Join(root, "coordinator", "work")
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil || len(history) != 1 {
		t.Fatalf("expected one retained test update: %v", err)
	}
	s := history[0]
	if s.Launcher != f.request.Candidate || !bytes.Equal(s.OriginalMap, f.original) || !bytes.Equal(s.TargetMap, f.target) {
		t.Fatal("retained update differs from the reviewed test fixture")
	}
	h, err := setupFileHash(s.Launcher)
	if err != nil || h != s.LauncherSHA256 {
		t.Fatal("selected candidate executable changed")
	}
	dir, err := guidedDirectory(s.SettingsRoot, s.Profile.Name, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	var p guidedProfile
	if err := setupReadJSON(filepath.Join(dir, "profile.json"), &p); err != nil {
		t.Fatal(err)
	}
	oldCommit := releaseCommit
	releaseCommit = f.request.Declaration.TargetApp
	t.Cleanup(func() { releaseCommit = oldCommit })
	_, d, selected, err := upgradeV2Selected(p, s.SettingsRoot, false)
	wantDeclaration := f.request.Declaration
	// The retained fixture generated its own report at activation. That exact
	// report is independently checked by upgradeV2Selected, not regenerated.
	wantDeclaration.QualificationSHA256 = d.QualificationSHA256
	if err != nil || !selected || !reflect.DeepEqual(d, wantDeclaration) {
		t.Fatalf("retained selection validation failed: %v", err)
	}
	// The actual selected executable also validates its own identity and opens
	// the retained journal. Q authorizes no ceremony operation.
	runRealUpgradeTerminal(t, s.Launcher, []string{"ceremony", "guide", p.Name, "--role", "coordinator", "--settings-root", s.SettingsRoot}, "Q\n", 10*time.Minute)
	driver := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: dockerCeremonyBinary, root: filepath.Join(work, "ceremony", "public"), inspectionRoot: work, definition: filepath.Join(work, "ceremony", "public", "ceremony.json"), definitionSig: filepath.Join(work, "ceremony", "public", "ceremony.sig"), coordinatorKey: filepath.Join(p.Trust, "setup-coordinator.hex"), client: osDockerCommandClient{binary: workflowV4LiveDockerCLI(t)}}
	inspector := driver.inspector()
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	var config access.StorageConfig
	if err := setupReadJSON(filepath.Join(work, "ceremony", "config", "relay-storage.json"), &config); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	requireAWSLiveConfiguration(t, config)
	if config.CeremonyID != protocol.Definition.CeremonyID || protocol.Definition.Mode != "rehearsal" {
		t.Fatal("expected exact retained rehearsal")
	}
	coordinator := reopenWorkflowV4LiveRole(t, root, "coordinator", protocol)
	defer coordinator.journal.close()
	if p.Work != coordinator.profile.Work || p.Trust != coordinator.profile.Trust || p.Keys != coordinator.profile.Keys || p.Image != coordinator.profile.Image || p.Platform != coordinator.profile.Platform {
		t.Fatal("saved profile differs from original journal binding")
	}
	coordinator.profile = p
	coordinator.profile.UpgradeOnlineImage = d.OnlineImage
	coordinator.signer.ReleaseCommit = d.OriginalRelease
	releaseSigner := reopenWorkflowV4LiveRole(t, root, "release-signer", protocol)
	defer releaseSigner.journal.close()
	previousExecutor := workflowV4ChildExecutor
	workflowV4ChildExecutor = func(args []string) error {
		binary := f.request.Predecessors[d.SourceApp]
		for i, arg := range args {
			if arg == "--work" && i+1 < len(args) && args[i+1] == work {
				binary = s.Launcher
			}
		}
		command := exec.Command(binary, args...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		return command.Run()
	}
	t.Cleanup(func() { workflowV4ChildExecutor = previousExecutor })
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}
	for step := 0; step < 5; step++ {
		snapshot := syncWorkflowV4LiveRole(t, &coordinator, objects)
		view, err := snapshot.State()
		if err != nil {
			t.Fatal(err)
		}
		if view.Progress.FinalRelease != nil {
			break
		}
		commitments, err := snapshot.Commitments()
		if err != nil {
			t.Fatal(err)
		}
		action, _, err := workflowV4CoordinatorLifecycleAction(view, commitments, protocol)
		if err != nil {
			t.Fatal(err)
		}
		// Renew between commands, never change an in-flight credential file.
		coordinator.profile.Credentials = freshAWSLiveCredentials(t)
		switch action {
		case workflowV4BeaconPhase2:
			beacon := filepath.Join(work, "ceremony", "public", "phase2", "beacon")
			before := map[string]string{}
			for _, name := range []string{"record.json", "record.sig", "raw-response.bin"} {
				path := filepath.Join(beacon, name)
				hash, err := setupFileHash(path)
				if err != nil {
					t.Fatal("missing retained beacon", err)
				}
				before[path] = hash
			}
			runWorkflowV4LiveBeacon(t, objects, protocol, &coordinator, action, "RECORD PHASE2 BEACON\n")
			for path, want := range before {
				got, err := setupFileHash(path)
				if err != nil || got != want {
					t.Fatal("resume changed retained beacon")
				}
			}
		case workflowV4Finalize:
			runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, action, "FINALIZE CANDIDATE\n")
		case workflowV4Review:
			runWorkflowV4LiveLifecycle(t, objects, protocol, &coordinator, action, "SIGN EVIDENCE BUNDLE\n")
		case workflowV4Release:
			grant, grantPath, err := workflowV4CurrentReleaseGrant(snapshot, protocol, config, work, releaseSigner.identity.ID, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if grant == nil {
				if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI("CREATE RELEASE GRANT\n"), action, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
					t.Fatal(err)
				}
				grant, grantPath, err = workflowV4CurrentReleaseGrant(snapshot, protocol, config, work, releaseSigner.identity.ID, time.Now().UTC())
				if err != nil || grant == nil {
					t.Fatalf("missing release grant: %v", err)
				}
			}
			rs := syncWorkflowV4LiveRole(t, &releaseSigner, objects)
			progress, err := workflowV4ReleaseSignerProgressFor(releaseSigner.profile.Work)
			if err != nil {
				t.Fatal(err)
			}
			if !progress.PackageReady {
				if err := runWorkflowV4ReleaseSignerAction(workflowV4LiveUI("SIGN RELEASE PACKAGE\n"), rs, protocol, config, releaseSigner.profile, releaseSigner.signer, releaseSigner.identity, progress); err != nil {
					t.Fatal(err)
				}
				progress, err = workflowV4ReleaseSignerProgressFor(releaseSigner.profile.Work)
				if err != nil {
					t.Fatal(err)
				}
			}
			received := filepath.Join(work, "workflow-v4", "coordinator", "release", "received", grant.AttemptID)
			input := "VERIFY AND RECORD RELEASE\n"
			if _, err := os.Lstat(received); errors.Is(err, os.ErrNotExist) {
				if err := runWorkflowV4ReleaseSignerAction(workflowV4LiveUI(grantPath+"\nUPLOAD RELEASE PACKAGE\n"), rs, protocol, config, releaseSigner.profile, releaseSigner.signer, releaseSigner.identity, progress); err != nil {
					t.Fatal(err)
				}
				input = "CHECK RELEASE INBOX\n" + input
			} else if err != nil {
				t.Fatal(err)
			}
			coordinator.profile.Credentials = freshAWSLiveCredentials(t)
			if err := runWorkflowV4CoordinatorLifecycle(workflowV4LiveUI(input), action, snapshot, protocol, coordinator.profile, coordinator.signer, coordinator.inspector); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("refuse to resume unexpected stage %s", action)
		}
	}
	freshRoot := t.TempDir()
	freshTranscript := filepath.Join(freshRoot, "ceremony", "public")
	freshTrust := filepath.Join(freshRoot, "trust")
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		copyWorkflowV4LiveFile(t, filepath.Join(work, "ceremony", "public", name), filepath.Join(freshTranscript, name))
	}
	copyWorkflowV4LiveFile(t, filepath.Join(p.Trust, "setup-coordinator.hex"), filepath.Join(freshTrust, "coordinator-public-key.hex"))
	freshInspector := workflowV4LiveFreshInspector(t, p, freshRoot, freshTranscript, freshTrust)
	highWater, err := state.OpenWorkspaceHighWater(filepath.Join(freshRoot, "high-water"), protocol.Definition.CeremonyID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := storagefirst.SyncV4(objects, freshInspector, highWater, protocol.Definition.CeremonyID, freshRoot)
	if err != nil {
		t.Fatal(err)
	}
	view, err := terminal.State()
	if err != nil || view.Progress.FinalRelease == nil {
		t.Fatalf("fresh client did not reconstruct final release: %v", err)
	}
	for path, want := range s.Bindings {
		got, err := setupFileHash(path)
		if err != nil || got != want {
			t.Fatal("frozen inputs changed")
		}
	}
	t.Log("AWS retained upgrade ceremony completed and final release reconstructed by a fresh client; test-only update authorization")
}

// Read-only role action: refresh public files and report the next instruction.
// No contribution, signing, grant issuance or upload is authorized by this test.
func TestUpgradeInspectRetainedParticipant(t *testing.T) {
	work := os.Getenv("RELAY_UPGRADE_INSPECT_WORK")
	if work == "" {
		t.Skip("requires a retained test participant workspace")
	}
	var saved workflowV4State
	if err := setupReadJSON(filepath.Join(work, "workflow-v4", "state.json"), &saved); err != nil {
		t.Fatal(err)
	}
	b := saved.Marker.Binding
	if b.Work != work || b.Role != "participant" {
		t.Fatal("wrong retained role")
	}
	r := b.Runtimes["contributor"]
	root := filepath.Join(work, "ceremony", "public")
	cli := workflowV4LiveDockerCLI(t)
	driver := dockerDriver{image: r.Image, platform: r.Platform, ceremonyBinary: dockerCeremonyBinary, root: root, inspectionRoot: work, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: filepath.Join(r.Mounts["/trust"], "coordinator-public-key.hex"), client: osDockerCommandClient{binary: cli}}
	inspector := driver.inspector()
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		t.Fatal(err)
	}
	j, err := openWorkflowV4Journal(protocol, protocol.DefinitionRefs, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	var config access.StorageConfig
	if err := setupReadJSON(filepath.Join(work, "ceremony", "config", "relay-storage.json"), &config); err != nil {
		t.Fatal(err)
	}
	snapshot, err := j.syncV4(store.Client{PublicBaseURL: config.PublishedBaseURL}, inspector, cli)
	if err != nil {
		t.Fatal(err)
	}
	view, err := snapshot.TurnV4(protocol, "phase1", b.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := j.participantProgressV4(view.Scope, cli)
	if err != nil {
		t.Fatal(err)
	}
	recommendation, err := workflowV4ParticipantRecommendation(snapshot, protocol, access.RoleConfig{IdentityID: b.IdentityID, Phase: "phase1"}, progress, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("next action=%s; reason=%s; local operations=%d", recommendation.Action, recommendation.Reason, len(j.state.Operations))
}
