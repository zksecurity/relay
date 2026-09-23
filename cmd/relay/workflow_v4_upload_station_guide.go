package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// An upload station has no signing identity. Its authority comes from the
// authenticated release-signer assignment and a scoped private upload grant.
// Keep it outside the participant/signer journal, whose binding requires a
// private key belonging to the role opening it.
func runWorkflowV4UploadStationGuide(p guidedProfile) error {
	if p.Role != "upload-station" || len(p.Command) != 0 || p.Credentials != "" || p.R2Parent != "" || p.R2Control != "" {
		return errors.New("upload-station guide requires a keyless online upload profile")
	}
	lock, err := acquireParticipantRunLock("", p.Work)
	if err != nil {
		return err
	}
	defer lock.release()
	// The setup profile records a keys directory for uniform onboarding. Never
	// pass it to the role launcher, even if files later appear in that directory.
	p.Keys = ""
	cli, err := exec.LookPath("docker")
	if err != nil {
		return err
	}
	cli, err = filepath.Abs(cli)
	if err != nil {
		return err
	}
	if err := prepareGuidedImage(p.Image, p.Platform, cli, false); err != nil {
		return err
	}
	root := filepath.Join(p.Work, "ceremony", "public")
	key := filepath.Join(p.Trust, "coordinator-public-key.hex")
	d := dockerDriver{runtimeLimits: p.Resources, image: p.Image, platform: p.Platform, ceremonyBinary: dockerCeremonyBinary, root: root, inspectionRoot: p.Work, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: key, client: osDockerCommandClient{binary: cli}}
	if err := d.authenticateDaemon(); err != nil {
		return err
	}
	ui := coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}
	if err := ensureGuidedResourcePolicy(&ui, d.client, d.daemon); err != nil {
		return err
	}
	inspector := d.inspector()
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		return fmt.Errorf("authenticate upload-station ceremony: %w", err)
	}
	if !protocol.UsesV4() {
		return errors.New("upload-station V4 guide requires a signed V4/V5 definition")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		return err
	}
	config, err := loadStorageConfig(filepath.Join(p.Work, "ceremony", "config", "relay-storage.json"))
	if err != nil {
		return err
	}
	if config.CeremonyID != protocol.Definition.CeremonyID {
		return errors.New("upload-station storage settings belong to another ceremony")
	}
	if err := validateStorageFirstOrigin("public storage address", config.PublishedBaseURL); err != nil {
		return err
	}
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}
	for {
		snapshot, err := syncWorkflowV4UploadStation(p, d, inspector, protocol, objects)
		if err != nil {
			return fmt.Errorf("authenticate current published checkpoint: %w", err)
		}
		stateView, err := snapshot.State()
		if err != nil {
			return err
		}
		fmt.Fprintf(ui.output, "Authenticated ceremony: %s\nSigned checkpoint: %s\n", protocol.Definition.CeremonyID, stateView.Transition.Kind)
		fmt.Fprintln(ui.output, "1) Verify and upload the release signer's public package\n2) Show required handoff")
		if stateView.Progress.FinalRelease != nil {
			fmt.Fprintln(ui.output, "3) Verify and publish a signed NO-GO trial archive")
		}
		fmt.Fprintln(ui.output, "0) Save and exit")
		choice, err := ui.ask("Choose upload-station action", "1")
		if err != nil {
			return err
		}
		switch choice {
		case "0":
			return nil
		case "2":
			fmt.Fprintf(ui.output, "Place the complete signed public release package at %s. Import the coordinator's private release upload grant through your private handoff. After a signed NO-GO, place the coordinator's public trial ZIP at %s. This station never receives a signing key.\n", filepath.Join(p.Work, "release"), filepath.Join(p.Work, "no-go-trial-ceremony.zip"))
		case "3":
			if stateView.Progress.FinalRelease == nil {
				return errors.New("a signed final release is required before trial publication")
			}
			if err := runWorkflowV4PublishNoGoTrial(&ui, p, config, protocol, snapshot); err != nil {
				return err
			}
		case "1":
			packageDir := filepath.Join(p.Work, "release")
			info, err := os.Lstat(packageDir)
			if err != nil {
				return fmt.Errorf("import the signed public release package into this upload workspace first: %w", err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("release handoff must be a real directory")
			}
			progress := workflowV4ReleaseSignerProgress{PackageDir: packageDir, PackageReady: true}
			if err := runWorkflowV4ReleaseUpload(&ui, snapshot, protocol, config, p, expected.Identity.ID, expected.Identity.KeyID, progress); err != nil {
				return err
			}
		default:
			return errors.New("choose a listed upload-station action")
		}
	}
}

func syncWorkflowV4UploadStation(p guidedProfile, d dockerDriver, trust transcript.Inspector, protocol transcript.DefinitionProtocol, objects storagefirst.ObjectStore) (storagefirst.SnapshotV4, error) {
	var zero storagefirst.SnapshotV4
	trust.Runner = func(executable string, args ...string) ([]byte, []byte, error) {
		if executable != "mpc-ceremony" && executable != "/usr/local/bin/mpc-ceremony" {
			return nil, nil, errors.New("unexpected upload-station metadata executable")
		}
		if len(args) < 4 || args[0] != "--format" || args[1] != "json" || args[2] != "checkpoint" || (args[3] != "inspect-signed-v4" && args[3] != "inspect-enrollments-v4") {
			return nil, nil, errors.New("upload-station sync cannot execute another command")
		}
		artifactRoot := commandValue(args, "artifact-root")
		if _, err := pathWithin(p.Work, artifactRoot, "/work"); err != nil {
			return nil, nil, err
		}
		child := d
		child.root = artifactRoot
		rewritten, mounts, err := child.rewriteReadOnlyArgs(args)
		if err != nil {
			return nil, nil, err
		}
		command := append(child.baseRunArgs(true, mounts), child.image)
		return child.admittedInspectionOutput(append(command, rewritten...))
	}
	trust.Executable = "mpc-ceremony"
	highWater, err := state.OpenWorkspaceHighWater(p.Work, protocol.Definition.CeremonyID)
	if err != nil {
		return zero, err
	}
	return storagefirst.SyncV4Retained(objects, trust, highWater, protocol.Definition.CeremonyID, p.Work, filepath.Join(p.Work, "ceremony", "public"))
}
