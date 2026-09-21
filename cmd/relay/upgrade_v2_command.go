package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/upgrade"
)

// Upgrade is a local application selection, not a ceremony transition. All
// downloads are authenticated before any selected entry point is changed.
func runCeremonyUpgradeV2(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony upgrade NAME --role ROLE --release role-images-COMMIT [--bundle DIR --trusted-root FILE]")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet("ceremony upgrade", flag.ContinueOnError)
	role := f.String("role", "", "saved ceremony role")
	target := f.String("release", "", "exact target release")
	approval := f.String("approval-release", "", "exact release publishing compatibility approval (defaults to target)")
	work := f.String("work", "", "existing role work folder for an unfinished setup")
	bundle := f.String("bundle", "", "previously prepared offline release bundle")
	trust := f.String("trusted-root", "", "independently installed Sigstore trust root for offline verification")
	f.StringVar(&root, "settings-root", root, "saved settings root")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || !launcherReleaseTag.MatchString(*target) {
		return errors.New("an exact target release is required")
	}
	targetCommit := strings.TrimPrefix(*target, "role-images-")
	approvalCommit, err := upgradeApprovalCommit(*approval, targetCommit)
	if err != nil {
		return err
	}
	if err := checkLauncherRelease(targetCommit); err != nil {
		return err
	}
	dir, err := guidedDirectory(root, args[0], *role)
	if err != nil {
		return err
	}
	lock, err := acquireParticipantRunLock("", filepath.Join(dir, "activity"))
	if err != nil {
		return err
	}
	defer lock.release()
	p, err := readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], *role)
	hasSharedProfile := err == nil
	var setup *upgradeSetupV2
	if errors.Is(err, os.ErrNotExist) && *work != "" {
		p, setup, err = upgradeV2DraftProfile(*work, args[0], *role)
	}
	if err == nil && setup == nil && *work != "" {
		draft, descriptor, e := upgradeV2DraftProfile(*work, args[0], *role)
		if e != nil {
			return e
		}
		draft.Image = p.Image
		if !upgradeV2FrozenProfileEqual(draft, p) {
			return errors.New("saved profile differs from setup installation")
		}
		p, setup = draft, descriptor
	}
	if err != nil {
		return err
	}
	if len(p.Command) != 0 || p.ReleaseCommit == "" {
		return errors.New("select the shared role profile, not a saved action")
	}
	// These are the currently connected storage-first journeys. Optional roles
	// cannot receive a broad declaration before their ordinary journey exists.
	if p.Role != "coordinator" && p.Role != "participant" && p.Role != "auditor" && p.Role != "release-signer" {
		return errors.New("this role has no qualified storage-first upgrade journey")
	}
	for _, path := range []string{p.Work, p.Trust, p.Keys, root} {
		if err := validateCommitLocalPath(path); err != nil {
			return err
		}
	}
	workLock, err := acquireParticipantRunLock("", p.Work)
	if err != nil {
		return err
	}
	defer workLock.release()
	releaseRelated, err := upgradeV2LockRelated(p, root, dir)
	if err != nil {
		return err
	}
	defer releaseRelated()
	if _, err := os.Lstat(upgradeSelectionPath(p)); err == nil {
		return errors.New("a v1 selection exists; preserve it and use its qualified v1 recovery path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	history, previous, err := upgradeV2ReadHistory(p.Work)
	if err != nil {
		return err
	}
	if len(history) > 0 && history[0].Setup != nil {
		setup = history[0].Setup
		// A draft-only lookup has no image yet. A real saved profile must match
		// every frozen field; never discard a changed config/platform/image.
		if p.Image == "" && !hasSharedProfile {
			p.Image = history[0].Profile.Image
		}
		if !upgradeV2FrozenProfileEqual(p, history[0].Profile) {
			return errors.New("prepared profile changed installation")
		}
		p = history[0].Profile
	}
	source, apps, err := upgradeV2Source(p)
	if err != nil {
		return err
	}
	if source == targetCommit && len(history) > 0 {
		s, _, _, err := upgradeV2Selected(p, root, true)
		if err != nil {
			return err
		}
		if *approval != "" {
			selectedApproval, err := upgradeApprovalCommit(s.ApprovalRelease, targetCommit)
			if err != nil || selectedApproval != approvalCommit {
				return errors.New("repair must retain the selected approval release")
			}
		}
		return upgradeV2FinishStart(s)
	}
	if source == targetCommit {
		return errors.New("this application is already the original release")
	}
	fmt.Fprintln(os.Stdout, "Exit every Relay session normally first. If a process was killed or a child may still be running, cancel and resolve that with the original runtime. Do not run other commands during this update. Have all sessions exited normally?")
	if err := confirmGuided(os.Stdin, os.Stdout); err != nil {
		return err
	}
	assets, cleanup, err := newUpgradeAssets(*bundle, *trust)
	if err != nil {
		return err
	}
	defer cleanup()
	originalMap, err := assets.get(p.ReleaseCommit, "relay-role-images.release.json")
	if err != nil {
		return err
	}
	if setup != nil && p.Image == "" {
		p.Image, err = selectReleaseImage(originalMap, p.ReleaseCommit, p.Role, p.Platform)
		if err != nil {
			return err
		}
	}
	targetMap, err := assets.get(targetCommit, "relay-role-images.release.json")
	if err != nil {
		return err
	}
	expected := upgrade.DeclarationV2{OriginalRelease: p.ReleaseCommit, SourceApp: source, TargetApp: targetCommit, Role: p.Role, Host: runtime.GOOS + "/" + runtime.GOARCH, Platform: p.Platform}
	raw, err := assets.get(approvalCommit, expected.AssetName())
	if err != nil {
		return fmt.Errorf("no authenticated compatibility declaration for this exact update: %w", err)
	}
	d, err := upgrade.DecodeV2(raw)
	if err != nil {
		return err
	}
	if d.OriginalRelease != expected.OriginalRelease || d.SourceApp != source || d.TargetApp != targetCommit || d.Role != p.Role || d.Host != expected.Host || d.Platform != p.Platform {
		return errors.New("compatibility declaration is for another installation")
	}
	if err := d.Cover(apps, upgradeV2RoleKinds(p.Role)); err != nil {
		return err
	}
	originalImage, err := selectReleaseImage(originalMap, p.ReleaseCommit, p.Role, p.Platform)
	if err != nil {
		return err
	}
	signingImage, err := selectReleaseImage(originalMap, p.ReleaseCommit, "decision-signer", p.Platform)
	if err != nil {
		return err
	}
	if originalImage != p.Image || d.OriginalImage != p.Image || d.SigningImage != signingImage {
		return errors.New("declaration differs from original authenticated images")
	}
	if d.OnlineImage != "" {
		image, err := upgradeV2DeclaredOnlineImage(originalMap, targetMap, d)
		if err != nil {
			return err
		}
		if image != d.OnlineImage {
			return errors.New("target image differs from its release")
		}
	}
	report, err := assets.get(approvalCommit, "upgrade-qualification-"+strings.TrimPrefix(d.QualificationSHA256, "sha256:")+".json")
	if err != nil {
		return err
	}
	q, err := upgrade.VerifyQualification(report, d)
	if err != nil {
		return err
	}
	if q.Schema != upgrade.CleanExitQualificationSchema {
		return errors.New("new updates require completed-step qualification; existing selections remain usable")
	}
	if "sha256:"+upgradeBytesHash(report) != d.QualificationSHA256 {
		return errors.New("qualification report hash mismatch")
	}
	launcher, err := assets.get(targetCommit, "relay-"+runtime.GOOS+"-"+runtime.GOARCH)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exeHash, err := setupFileHash(exe)
	if err != nil {
		return err
	}
	if upgradeBytesHash(launcher) != exeHash || q.LauncherSHA256 != "sha256:"+exeHash {
		return errors.New("running executable differs from the qualified attested binary")
	}
	for _, image := range []string{p.Image, signingImage, d.OnlineImage} {
		if image == "" {
			continue
		}
		hash, err := upgradeImageProofHashMode(image, p.Platform, *bundle == "")
		if err != nil {
			return err
		}
		if hash != d.ProofToolSHA256 {
			return errors.New("cryptographic runtime changed; not an application-only update")
		}
	}
	if setup != nil {
		if len(setup.Manifest) == 0 {
			setup.Manifest, err = assets.get(p.ReleaseCommit, "ceremony-software-manifest-v3.json")
			if err != nil {
				return err
			}
		}
		if err := upgradeV2SetupManifest(setup.Manifest, originalMap, p.ReleaseCommit, p.Platform, d.ProofToolSHA256); err != nil {
			return err
		}
	}
	cli, err := exec.LookPath("docker")
	if err != nil {
		return err
	}
	driver := dockerDriver{image: p.Image, platform: p.Platform, client: osDockerCommandClient{binary: cli}}
	if setup == nil {
		signerDir, err := guidedDirectory(root, offlineRoleAlias(p.Name, p.Role), "decision-signer")
		if err != nil {
			return err
		}
		signer, err := readGuidedProfile(filepath.Join(signerDir, "profile.json"), offlineRoleAlias(p.Name, p.Role), "decision-signer")
		if err != nil {
			return err
		}
		if signer.Image != signingImage {
			return errors.New("signing profile differs from original release")
		}
		var identity setupIdentity
		if err := setupReadJSON(filepath.Join(p.Keys, "identity.json"), &identity); err != nil {
			return err
		}
		cli, err := exec.LookPath("docker")
		if err != nil {
			return err
		}
		key := filepath.Join(p.Trust, "coordinator-public-key.hex")
		if p.Role == "coordinator" {
			key = filepath.Join(p.Trust, "setup-coordinator.hex")
		}
		var participant *access.RoleConfig
		if p.Role == "participant" {
			c, err := loadRoleConfig(p.Config, "participant")
			if err != nil {
				return err
			}
			participant = &c
			key = c.CoordinatorKey
		}
		driver = dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: dockerCeremonyBinary, root: filepath.Join(p.Work, "ceremony/public"), inspectionRoot: p.Work, definition: filepath.Join(p.Work, "ceremony/public/ceremony.json"), definitionSig: filepath.Join(p.Work, "ceremony/public/ceremony.sig"), coordinatorKey: key, client: osDockerCommandClient{binary: cli}}
		if err := driver.authenticateDaemon(); err != nil {
			return err
		}
		if err := upgradeCheckContainers(driver.client, p); err != nil {
			return err
		}
		protocol, err := driver.inspector().DefinitionProtocol()
		if err != nil {
			return err
		}
		if err := upgradeV2CheckApprovedProof(driver.definition, p.Platform, d.ProofToolSHA256); err != nil {
			return err
		}
		binding, err := workflowV4ProfileBinding(p, signer, protocol, identity, participant)
		if err != nil {
			return err
		}
		var journal workflowV4State
		if err := readWorkflowV4JSON(filepath.Join(p.Work, "workflow-v4/state.json"), &journal); err == nil {
			if err := validateWorkflowV4State(journal, binding, filepath.Join(p.Work, "workflow-v4/state.json")); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		storageRaw, err := readTesseraRegularFile(filepath.Join(p.Work, "ceremony/config/relay-storage.json"), 1<<20, false)
		if err != nil {
			return err
		}
		storage, err := access.Decode(storageRaw, access.StorageConfig.Validate)
		if err != nil {
			return err
		}
		if storage.CeremonyID != binding.CeremonyID {
			return errors.New("storage belongs to another ceremony")
		}
	}
	var bindings map[string]string
	if setup != nil {
		if len(history) > 0 {
			bindings = history[0].Bindings
		} else {
			bindings, setup.Absent, err = upgradeV2SetupContinuity(p)
		}
	} else {
		bindings, err = upgradeV2BindingFiles(p)
	}
	if err != nil {
		return err
	}
	inv, err := upgradeV2Inventory(p, d)
	if err != nil {
		return err
	}
	s := upgradeSelectionV2{Schema: upgradeSelectionV2Schema, Previous: previous, Declaration: raw, OriginalMap: originalMap, TargetMap: targetMap, Qualification: report, Profile: p, SettingsRoot: root, Bindings: bindings, Launcher: exe, LauncherSHA256: exeHash, StartPath: filepath.Join(filepath.Dir(p.Work), "start.sh"), InventorySHA256: inv.digest(), Kinds: inv.Kinds, Setup: setup}
	if approvalCommit != targetCommit {
		s.ApprovalRelease = "role-images-" + approvalCommit
	}
	s.PreviousStart, err = readTesseraRegularFile(s.StartPath, 64<<10, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Update %s application: %s → %s\nOriginal ceremony release: %s (unchanged)\nOriginal contribution and signing images remain pinned.\nInventoried %d files and %d retained operations. No ceremony command will be replayed by this update.\n", p.Role, source, targetCommit, p.ReleaseCommit, len(inv.Files), len(inv.Pending))
	fmt.Fprintf(os.Stdout, "Compatibility approval release: role-images-%s (reviewed local test evidence; not a claim that these tests ran in CI).\n", approvalCommit)
	for _, pending := range inv.Pending {
		fmt.Fprintln(os.Stdout, "  "+pending)
	}
	for _, gap := range inv.HistoryGaps {
		fmt.Fprintln(os.Stdout, "  Local activity limitation: "+gap)
	}
	if err := confirmGuided(os.Stdin, os.Stdout); err != nil {
		return err
	}
	current, err := readGuidedProfile(filepath.Join(dir, "profile.json"), p.Name, p.Role)
	if setup != nil {
		current, _, err = upgradeV2DraftProfile(p.Work, p.Name, p.Role)
		current.Image = p.Image
	}
	if err != nil {
		return err
	}
	if !upgradeV2FrozenProfileEqual(current, p) {
		return errors.New("profile changed during review")
	}
	var bindingsNow map[string]string
	if setup != nil {
		bindingsNow = map[string]string{}
		for path := range bindings {
			h, e := setupFileHash(path)
			if e != nil {
				return e
			}
			bindingsNow[path] = h
		}
	} else {
		bindingsNow, err = upgradeV2BindingFiles(p)
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bindings, bindingsNow) {
		return errors.New("frozen inputs changed during review")
	}
	again, err := upgradeV2Inventory(p, d)
	if err != nil {
		return err
	}
	if again.digest() != inv.digest() {
		return errors.New("retained work changed during review; nothing selected")
	}
	if err := driver.authenticateDaemon(); err != nil {
		return err
	}
	if err := upgradeCheckContainers(driver.client, p); err != nil {
		return err
	}
	if err := upgradeV2Activate(s, previous); err != nil {
		return err
	}
	return upgradeV2FinishStart(s)
}

// Call only after signature authentication by the original proof-tool.
func upgradeV2CheckApprovedProof(definition, platform, measured string) error {
	approved, err := signedCeremonyBinarySHA256(definition, platform)
	if err != nil {
		return err
	}
	if approved != measured {
		return errors.New("signed ceremony does not approve the measured proof-tool binary")
	}
	return nil
}

func upgradeV2FinishStart(s upgradeSelectionV2) error {
	if err := upgradeV2WriteStart(s); err != nil {
		return fmt.Errorf("update selected; start script was not changed. Rerun this update to repair it, or use %q ceremony guide %q --role %q --settings-root %q: %w", s.Launcher, s.Profile.Name, s.Profile.Role, s.SettingsRoot, err)
	}
	fmt.Fprintf(os.Stdout, "Application update selected. Resume using %q. Keys, signed ceremony files and retained progress were not replaced.\n", s.StartPath)
	return nil
}
