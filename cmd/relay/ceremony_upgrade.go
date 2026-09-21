package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/upgrade"
)

// An activation is local configuration on a trusted host, not a new trust
// anchor. Its declaration and both release maps are authenticated before save.
type ceremonyUpgradeSelection struct {
	Schema           string              `json:"schema"`
	Declaration      upgrade.Declaration `json:"declaration"`
	ProfileSHA256    string              `json:"profile_sha256"`
	SignerSHA256     string              `json:"signer_sha256"`
	DefinitionSHA256 string              `json:"definition_sha256"`
	SignatureSHA256  string              `json:"signature_sha256"`
	StorageSHA256    string              `json:"storage_sha256"`
	LauncherSHA256   string              `json:"launcher_sha256"`
	Launcher         string              `json:"launcher"`
	SourceMap        []byte              `json:"source_map"`
	TargetMap        []byte              `json:"target_map"`
	DeclarationBytes []byte              `json:"declaration_bytes"`
	StartPath        string              `json:"start_path"`
	PreviousStart    []byte              `json:"previous_start"`
	SettingsRoot     string              `json:"settings_root"`
}

const ceremonyUpgradeSchema = "relay-ceremony-upgrade-selection/v1"

func upgradeProfileHash(p guidedProfile) string {
	p.UpgradeOnlineImage = ""
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func upgradeSelectionPath(p guidedProfile) string {
	return filepath.Join(p.Work, "relay-upgrade.json")
}

func readUpgradeSelection(p guidedProfile, settingsRoot string) (ceremonyUpgradeSelection, error) {
	var s ceremonyUpgradeSelection
	if err := readWorkflowV4JSON(upgradeSelectionPath(p), &s); err != nil {
		return s, err
	}
	if s.Schema != ceremonyUpgradeSchema || s.Declaration.Validate() != nil ||
		s.Declaration.SourceRelease != p.ReleaseCommit || s.Declaration.TargetRelease != launcherCommit() ||
		s.Declaration.Role != p.Role || s.Declaration.Platform != p.Platform ||
		s.Declaration.SourceOnlineImage != p.Image || s.ProfileSHA256 != upgradeProfileHash(p) {
		return s, errors.New("saved upgrade does not match this launcher and original role profile")
	}
	if s.SettingsRoot != settingsRoot || s.StartPath != filepath.Join(filepath.Dir(p.Work), "start.sh") {
		return s, errors.New("upgrade entry point does not match this workspace")
	}
	d, err := upgrade.Decode(s.DeclarationBytes)
	if err != nil || d != s.Declaration {
		return s, errors.New("cached compatibility declaration changed")
	}
	for _, item := range []struct {
		raw           []byte
		commit, image string
	}{
		{s.SourceMap, d.SourceRelease, d.SourceOnlineImage},
		{s.TargetMap, d.TargetRelease, d.TargetOnlineImage},
	} {
		image, err := selectReleaseImage(item.raw, item.commit, p.Role, p.Platform)
		if err != nil || image != item.image {
			return s, errors.New("cached release map does not match upgrade")
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return s, err
	}
	h, err := setupFileHash(exe)
	if err != nil {
		return s, err
	}
	if h != s.LauncherSHA256 {
		return s, errors.New("upgraded launcher bytes changed; reinstall the verified release")
	}
	signerDir, err := guidedDirectory(settingsRoot, offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return s, err
	}
	signer, err := readGuidedProfile(filepath.Join(signerDir, "profile.json"), offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return s, err
	}
	if upgradeProfileHash(signer) != s.SignerSHA256 {
		return s, errors.New("original signing profile changed after upgrade")
	}
	for _, item := range []struct{ path, hash string }{
		{filepath.Join(p.Work, "ceremony/public/ceremony.json"), s.DefinitionSHA256},
		{filepath.Join(p.Work, "ceremony/public/ceremony.sig"), s.SignatureSHA256},
		{filepath.Join(p.Work, "ceremony/config/relay-storage.json"), s.StorageSHA256},
	} {
		h, err := setupFileHash(item.path)
		if err != nil {
			return s, err
		}
		if h != item.hash {
			return s, errors.New("ceremony or storage binding changed after upgrade")
		}
	}
	return s, nil
}

// No global release-match bypass: only the V4 coordinator guide consumes this.
func applyCeremonyUpgrade(p guidedProfile, settingsRoot string) (guidedProfile, error) {
	if upgraded, found, err := upgradeV2Resolve(p, settingsRoot); err != nil {
		return p, err
	} else if found {
		return upgraded, nil
	}
	if err := checkLauncherRelease(p.ReleaseCommit); err == nil {
		return p, nil
	}
	if p.Role != "coordinator" || len(p.Command) != 0 {
		return p, checkLauncherRelease(p.ReleaseCommit)
	}
	s, err := readUpgradeSelection(p, settingsRoot)
	if err != nil {
		return p, fmt.Errorf("no compatible upgrade activated: %w", err)
	}
	p.UpgradeOnlineImage = s.Declaration.TargetOnlineImage
	return p, nil
}

func upgradeDownload(dir, commit, asset string) ([]byte, error) {
	if !launcherReleaseTag.MatchString("role-images-"+commit) || filepath.Base(asset) != asset {
		return nil, errors.New("invalid release asset")
	}
	file := filepath.Join(dir, asset)
	for _, args := range [][]string{
		{"release", "download", "role-images-" + commit, "--repo", "zksecurity/relay", "--pattern", asset, "--dir", dir},
		{"attestation", "verify", file, "--repo", "zksecurity/relay", "--signer-workflow", "zksecurity/relay/.github/workflows/publish-role-images.yml", "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"},
	} {
		c := exec.Command("gh", args...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return nil, fmt.Errorf("verify release asset %s: %w", asset, err)
		}
	}
	maximum := int64(1 << 20)
	if strings.HasPrefix(asset, "relay-darwin-") || strings.HasPrefix(asset, "relay-linux-") {
		maximum = 128 << 20
	}
	return readTesseraRegularFile(file, maximum, false)
}

func upgradeImageProofHash(image, platform string) (string, error) {
	return upgradeImageProofHashMode(image, platform, true)
}

func upgradeImageProofHashMode(image, platform string, pull bool) (string, error) {
	cli, err := exec.LookPath("docker")
	if err != nil {
		return "", err
	}
	if err := prepareGuidedImage(image, platform, cli, pull); err != nil {
		return "", err
	}
	client := osDockerCommandClient{binary: cli}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return "", err
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return "", err
	}
	// The offline image is scratch: no shell or checksum utility exists. Copy
	// the actual binary from a never-started, unmounted container and hash it
	// locally. This does not substitute or execute a host Proof-tool binary.
	bound := client.BindHost(endpoint)
	raw, _, err := bound.Output("create", "--pull=never", "--platform", platform, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit=core=0:0", "--log-driver=none", "--entrypoint="+dockerCeremonyBinary, image)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !validContainerID(id) {
		return "", errors.New("invalid measurement container ID")
	}
	defer bound.Output("rm", id)
	dir, err := os.MkdirTemp("", "relay-image-measurement-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mpc-ceremony")
	if _, _, err := bound.Output("cp", id+":"+dockerCeremonyBinary, path); err != nil {
		return "", err
	}
	hash, err := setupFileHash(path)
	if err != nil {
		return "", err
	}
	if _, _, err := bound.Output("rm", id); err != nil {
		return "", errors.New("could not remove the stopped image-measurement container")
	}
	return "sha256:" + hash, nil
}

func runCeremonyUpgrade(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony upgrade NAME --role coordinator --release role-images-COMMIT")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet("ceremony upgrade", flag.ContinueOnError)
	role := f.String("role", "", "saved role")
	target := f.String("release", "", "target attested release")
	f.StringVar(&root, "settings-root", root, "saved settings root")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) != 0 || *role != "coordinator" || !launcherReleaseTag.MatchString(*target) {
		return errors.New("initial upgrade support requires coordinator and an exact target release")
	}
	targetCommit := strings.TrimPrefix(*target, "role-images-")
	if err := checkLauncherRelease(targetCommit); err != nil {
		return err
	}
	dir, err := guidedDirectory(root, args[0], *role)
	if err != nil {
		return err
	}
	profileLock, err := acquireParticipantRunLock("", filepath.Join(dir, "activity"))
	if err != nil {
		return err
	}
	defer profileLock.release()
	p, err := readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], *role)
	if err != nil {
		return err
	}
	if len(p.Command) != 0 || p.ReleaseCommit == "" || p.ReleaseCommit == targetCommit {
		return errors.New("upgrade requires shared settings from a different released version")
	}
	for _, path := range []string{p.Work, p.Trust, p.Keys} {
		if err := validateCommitLocalPath(path); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("role folder is not a directory")
		}
	}
	// Hold the same workspace lock as the old and new V4 guides.
	workLock, err := acquireParticipantRunLock("", p.Work)
	if err != nil {
		return err
	}
	defer workLock.release()
	if _, err := os.Lstat(upgradeSelectionPath(p)); err == nil {
		s, err := readUpgradeSelection(p, root)
		if err != nil {
			return err
		}
		if err := upgradeInstallStart(s, p); err != nil {
			return err
		}
		fmt.Printf("This compatible upgrade is already active. Resume with %s\n", s.StartPath)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintln(os.Stdout, "Before upgrading: exit all Relay sessions normally and wait for every action to finish. Do not start another command until this upgrade finishes. If a session was killed, lost, or may have left a child running, cancel: this upgrade cannot establish safe recovery from that condition. Have all sessions exited normally?")
	if err := confirmGuided(os.Stdin, os.Stdout); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "relay-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	sourceDir := filepath.Join(tmp, "source")
	targetDir := filepath.Join(tmp, "target")
	for _, d := range []string{sourceDir, targetDir} {
		if err := os.Mkdir(d, 0700); err != nil {
			return err
		}
	}
	sourceMap, err := upgradeDownload(sourceDir, p.ReleaseCommit, "relay-role-images.release.json")
	if err != nil {
		return err
	}
	targetMap, err := upgradeDownload(targetDir, targetCommit, "relay-role-images.release.json")
	if err != nil {
		return err
	}
	sourceImage, err := selectReleaseImage(sourceMap, p.ReleaseCommit, p.Role, p.Platform)
	if err != nil {
		return err
	}
	targetImage, err := selectReleaseImage(targetMap, targetCommit, p.Role, p.Platform)
	if err != nil {
		return err
	}
	if sourceImage != p.Image {
		return errors.New("saved image differs from the authenticated original release")
	}
	asset := fmt.Sprintf("upgrade-%s-%s-%s.json", p.ReleaseCommit, p.Role, strings.TrimPrefix(p.Platform, "linux/"))
	raw, err := upgradeDownload(targetDir, targetCommit, asset)
	if err != nil {
		return err
	}
	declaration, err := upgrade.Decode(raw)
	if err != nil {
		return err
	}
	if declaration.Role != p.Role || declaration.Platform != p.Platform {
		return errors.New("compatibility declaration targets another role/platform")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	launcherBytes, err := upgradeDownload(targetDir, targetCommit, "relay-"+runtime.GOOS+"-"+runtime.GOARCH)
	if err != nil {
		return err
	}
	exeHash, err := setupFileHash(exe)
	if err != nil {
		return err
	}
	assetHash := sha256.Sum256(launcherBytes)
	if hex.EncodeToString(assetHash[:]) != exeHash {
		return errors.New("running launcher is not the attested target asset")
	}
	sourceHash, err := upgradeImageProofHash(sourceImage, p.Platform)
	if err != nil {
		return err
	}
	targetHash, err := upgradeImageProofHash(targetImage, p.Platform)
	if err != nil {
		return err
	}
	if err := declaration.Match(upgrade.Installation{Release: p.ReleaseCommit, OnlineImage: sourceImage, ProofToolSHA256: sourceHash}, upgrade.Installation{Release: targetCommit, OnlineImage: targetImage, ProofToolSHA256: targetHash}); err != nil {
		return err
	}
	signerDir, err := guidedDirectory(root, offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return err
	}
	signer, err := readGuidedProfile(filepath.Join(signerDir, "profile.json"), offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return err
	}
	expectedSigner, err := selectReleaseImage(sourceMap, p.ReleaseCommit, "decision-signer", p.Platform)
	if err != nil {
		return err
	}
	if signer.Image != expectedSigner {
		return errors.New("signing image differs from original release")
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(p.Keys, "identity.json"), &identity); err != nil {
		return err
	}
	cli, err := exec.LookPath("docker")
	if err != nil {
		return err
	}
	driver := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: dockerCeremonyBinary, root: filepath.Join(p.Work, "ceremony/public"), inspectionRoot: p.Work, definition: filepath.Join(p.Work, "ceremony/public/ceremony.json"), definitionSig: filepath.Join(p.Work, "ceremony/public/ceremony.sig"), coordinatorKey: filepath.Join(p.Trust, "setup-coordinator.hex"), client: osDockerCommandClient{binary: cli}}
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
	binding, err := workflowV4ProfileBinding(p, signer, protocol, identity, nil)
	if err != nil {
		return err
	}
	if err := upgradeCheckJournal(p, binding); err != nil {
		return err
	}
	if err := upgradeCheckInitialArtifacts(p); err != nil {
		return err
	}
	storagePath := filepath.Join(p.Work, "ceremony/config/relay-storage.json")
	storageRaw, err := readTesseraRegularFile(storagePath, 1<<20, false)
	if err != nil {
		return err
	}
	config, err := access.Decode(storageRaw, access.StorageConfig.Validate)
	if err != nil {
		return err
	}
	if config.CeremonyID != binding.CeremonyID {
		return errors.New("storage belongs to another ceremony")
	}
	s := ceremonyUpgradeSelection{Schema: ceremonyUpgradeSchema, Declaration: declaration, ProfileSHA256: upgradeProfileHash(p), SignerSHA256: upgradeProfileHash(signer), Launcher: exe, LauncherSHA256: exeHash, SourceMap: sourceMap, TargetMap: targetMap, DeclarationBytes: raw}
	s.SettingsRoot = root
	s.StartPath = filepath.Join(filepath.Dir(p.Work), "start.sh")
	s.PreviousStart, err = readTesseraRegularFile(s.StartPath, 64<<10, false)
	if err != nil {
		return fmt.Errorf("cannot preserve existing start.sh: %w", err)
	}
	for _, item := range []struct {
		path string
		dest *string
	}{
		{driver.definition, &s.DefinitionSHA256}, {driver.definitionSig, &s.SignatureSHA256}, {storagePath, &s.StorageSHA256},
	} {
		*item.dest, err = setupFileHash(item.path)
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stdout, "Upgrade coordinator Relay from %s to %s\nOnline image: %s\nProof-tool SHA-256: %s (unchanged)\nSigning image and ceremony records remain pinned.\n", p.ReleaseCommit, targetCommit, targetImage, sourceHash)
	if err := confirmGuided(os.Stdin, os.Stdout); err != nil {
		return err
	}
	// Recheck after confirmation: operator time is unbounded. Normal source
	// exits are required; a killed parent can leave a not-yet-created child.
	if err := upgradeCheckJournal(p, binding); err != nil {
		return err
	}
	if err := upgradeCheckInitialArtifacts(p); err != nil {
		return err
	}
	if err := driver.authenticateDaemon(); err != nil {
		return err
	}
	if err := upgradeCheckContainers(driver.client, p); err != nil {
		return err
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := publishPublicInput(upgradeSelectionPath(p), encoded); err != nil {
		return err
	}
	if err := upgradeInstallStart(s, p); err != nil {
		return fmt.Errorf("upgrade selection saved; rerun this upgrade command to finish start.sh activation: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Upgrade activated. Resume with:\n  %q\nThe original start script is preserved in the protected upgrade selection.\n", s.StartPath)
	return nil
}

// The first activation scope is intentionally before coordinator storage
// actions. Later checkpoints/partial closure outputs have recovery semantics
// not covered by the generic journal, even if no intent file exists.
func upgradeCheckInitialArtifacts(p guidedProfile) error {
	root := filepath.Join(p.Work, "ceremony", "public")
	allowed := map[string]bool{
		"ceremony.json": true, "ceremony.sig": true, "coordinator-public-key.hex": true,
		"ownership-destination.ccs": true, "phase1/genesis.bin": true,
		"phase1/chain-0000.json": true, "phase1/chain-0000.sig": true,
		"checkpoints/initial/checkpoint.json": true, "checkpoints/initial/checkpoint.sig": true,
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in retained ceremony artifacts")
		}
		if entry.IsDir() {
			if rel == "." || rel == "phase1" || rel == "checkpoints" || rel == "checkpoints/initial" {
				return nil
			}
			return errors.New("upgrade after coordinator storage actions is not yet qualified; use original release")
		}
		if !entry.Type().IsRegular() || !allowed[rel] {
			return errors.New("retained ceremony work is outside the qualified upgrade activation scope")
		}
		return nil
	})
}

func upgradeStartBytes(s ceremonyUpgradeSelection, p guidedProfile) []byte {
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	return []byte("#!/usr/bin/env bash\nset -euo pipefail\nexec " + quote(s.Launcher) + " ceremony guide " + quote(p.Name) + " --role " + quote(p.Role) + " --settings-root " + quote(s.SettingsRoot) + "\n")
}

// Selection is durable first. A crash before rename leaves the old script;
// rerunning upgrade completes activation without rewriting ceremony state.
func upgradeInstallStart(s ceremonyUpgradeSelection, p guidedProfile) error {
	return upgradeInstallStartBytes(s, p, upgradeStartBytes(s, p))
}

func upgradeInstallStartBytes(s ceremonyUpgradeSelection, p guidedProfile, next []byte) error {
	if s.StartPath != filepath.Join(filepath.Dir(p.Work), "start.sh") {
		return errors.New("invalid upgrade entry point")
	}
	current, err := readTesseraRegularFile(s.StartPath, 64<<10, false)
	if err != nil {
		return err
	}
	if string(current) == string(next) {
		return nil
	}
	if string(current) != string(s.PreviousStart) {
		return errors.New("start.sh changed since review; preserved without replacement")
	}
	f, err := os.CreateTemp(filepath.Dir(s.StartPath), ".relay-upgrade-start-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(next); err == nil {
		err = f.Chmod(0700)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), s.StartPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.StartPath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// A point-in-time guard, NOT proof of quiescence after a killed source process.
// The operator must also confirm normal child completion. Check all statuses:
// a stopped/created container can still be restarted against the workspace.
func upgradeCheckContainers(client dockerCommandClient, p guidedProfile) error {
	ids, _, err := client.Output("ps", "--all", "--quiet", "--no-trunc")
	if err != nil {
		return fmt.Errorf("cannot check retained containers: %w", err)
	}
	for _, id := range strings.Fields(string(ids)) {
		if len(id) != 64 {
			return errors.New("invalid Docker container identity")
		}
		if _, err := hex.DecodeString(id); err != nil {
			return errors.New("invalid Docker container identity")
		}
		raw, _, err := client.Output("inspect", "--type=container", id)
		if err != nil {
			return errors.New("container changed during upgrade inspection; retry after clean completion")
		}
		if err := upgradeCheckMounts(raw, p); err != nil {
			return err
		}
	}
	return nil
}

func upgradeCheckMounts(raw []byte, p guidedProfile) error {
	var entries []struct {
		Mounts []struct{ Type, Source string }
	}
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != 1 || entries[0].Mounts == nil {
		return errors.New("cannot inspect container mounts")
	}
	for _, mount := range entries[0].Mounts {
		if mount.Type != "bind" {
			continue
		}
		if !filepath.IsAbs(mount.Source) {
			return errors.New("invalid container bind mount")
		}
		for _, root := range []string{p.Work, p.Trust, p.Keys} {
			if !filepath.IsAbs(root) {
				return errors.New("invalid role folder")
			}
			a, b := filepath.Clean(mount.Source), filepath.Clean(root)
			// Docker Desktop may report /private/var for the host's /var path.
			if resolved, err := filepath.EvalSymlinks(a); err == nil {
				a = resolved
			}
			if resolved, err := filepath.EvalSymlinks(b); err == nil {
				b = resolved
			}
			contains := func(parent, child string) bool {
				rel, err := filepath.Rel(parent, child)
				return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
			}
			if contains(a, b) || contains(b, a) {
				return errors.New("a retained Docker container mounts this role's folders; finish and remove it with the original runtime before upgrading")
			}
		}
	}
	return nil
}

func upgradeCheckJournal(p guidedProfile, b workflowV4Binding) error {
	statePath := filepath.Join(p.Work, "workflow-v4/state.json")
	var state workflowV4State
	if err := readWorkflowV4JSON(statePath, &state); err != nil {
		return fmt.Errorf("open existing ceremony operations once with the original release before upgrading: %w", err)
	}
	if err := validateWorkflowV4State(state, b, statePath); err != nil {
		return err
	}
	var marker workflowV4Marker
	if err := readWorkflowV4JSON(filepath.Join(p.Work, ".relay-workspace-v4.json"), &marker); err != nil {
		return err
	}
	a, _ := json.Marshal(marker)
	c, _ := json.Marshal(state.Marker)
	if string(a) != string(c) {
		return errors.New("workspace marker differs from journal")
	}
	for _, op := range state.Operations {
		switch op.Status {
		case "reconciled", "abandoned", "failed-no-effects":
		default:
			return errors.New("resolve retained operation with its original runtime before upgrading")
		}
	}
	// These records are NOT represented in state.Operations. Until recovery of
	// each is qualified, never infer that an empty generic journal means idle.
	for _, name := range []string{"coordinator", "lifecycle", "commits"} {
		path := filepath.Join(p.Work, "workflow-v4", name)
		if info, err := os.Lstat(path); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe retained coordinator path")
			}
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(entries) != 0 {
				return errors.New("retained coordinator work is not yet supported by upgrade; keep the original runtime")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
