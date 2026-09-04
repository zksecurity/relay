package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	dockerExecutionMode       = "docker"
	nativeExecutionMode       = "native"
	dockerLifecycleSchema     = "relay-docker-lifecycle-v1"
	dockerActiveStateSchema   = "relay-docker-active-container-v1"
	dockerLifecycleLogName    = "relay-lifecycle.json"
	dockerActiveStateFileName = ".relay-active-container.json"
)

type dockerCommandClient interface {
	Output(args ...string) ([]byte, []byte, error)
	Attached(stdout, stderr io.Writer, args ...string) error
}

type osDockerCommandClient struct{ binary string }

func (c osDockerCommandClient) Output(args ...string) ([]byte, []byte, error) {
	command := exec.Command(c.binary, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (c osDockerCommandClient) Attached(stdout, stderr io.Writer, args ...string) error {
	command := exec.Command(c.binary, args...)
	command.Stdout, command.Stderr = stdout, stderr
	command.Stdin = os.Stdin
	return command.Run()
}

type dockerMount struct {
	Source      string
	Destination string
	ReadOnly    bool
}

type dockerDriver struct {
	image          string
	platform       string
	ceremonyBinary string
	root           string
	definition     string
	definitionSig  string
	coordinatorKey string
	signingKey     string
	environment    string
	candidateRoot  string
	client         dockerCommandClient
	now            func() time.Time
	hostSwapStatus func() (string, error)
}

type dockerActiveState struct {
	Schema      string `json:"schema"`
	ContainerID string `json:"container_id"`
	Image       string `json:"image"`
	Platform    string `json:"platform"`
	HandoffDir  string `json:"handoff_dir"`
	CreatedAt   string `json:"created_at"`
}

type dockerSecurityFacts struct {
	NetworkNone     bool `json:"network_none"`
	ReadOnlyRoot    bool `json:"read_only_root"`
	NonRoot         bool `json:"non_root"`
	CapabilitiesOff bool `json:"capabilities_dropped"`
	NoNewPrivileges bool `json:"no_new_privileges"`
	CoreDumpsOff    bool `json:"core_dumps_disabled"`
	LogDriverOff    bool `json:"log_driver_disabled"`
	PrivatePID      bool `json:"private_pid_namespace"`
	PrivateIPC      bool `json:"private_ipc_namespace"`
	NoHostUserNS    bool `json:"no_host_user_namespace"`
	BoundedTmpfs    bool `json:"bounded_tmpfs"`
	MountsVerified  bool `json:"mounts_verified"`
}

type dockerLifecycleReceipt struct {
	Schema                  string              `json:"schema"`
	ExecutionMode           string              `json:"execution_mode"`
	Image                   string              `json:"image"`
	Platform                string              `json:"platform"`
	CeremonyBinary          string              `json:"ceremony_binary"`
	CeremonyBinarySHA256    string              `json:"ceremony_binary_sha256"`
	HostSwapStatus          string              `json:"host_swap_status"`
	ContainerID             string              `json:"container_id"`
	CreatedAt               string              `json:"created_at"`
	StartedAt               string              `json:"started_at"`
	ExitedAt                string              `json:"exited_at"`
	ExitCode                int                 `json:"exit_code"`
	RemovedAt               string              `json:"removed_at"`
	RemovalVerified         bool                `json:"removal_verified"`
	Security                dockerSecurityFacts `json:"security"`
	ParticipantConfirmation string              `json:"participant_confirmation,omitempty"`
	ConfirmedAt             string              `json:"confirmed_at,omitempty"`
}

func dockerDriverForParticipant(config access.ParticipantConfig) *dockerDriver {
	return &dockerDriver{
		image: config.DockerImage, platform: config.DockerPlatform, ceremonyBinary: config.CeremonyBinary,
		root: config.Root, definition: config.Ceremony, definitionSig: config.CeremonySignature,
		coordinatorKey: config.CoordinatorKey, signingKey: config.SigningKey, environment: config.Environment,
		candidateRoot: config.CandidateParentDir,
		client:        osDockerCommandClient{binary: config.DockerCLI}, now: time.Now,
	}
}

func effectiveExecutionMode(mode string) string {
	if mode == "" {
		return nativeExecutionMode
	}
	return mode
}

// inspectionRunner lets the existing authenticated projections run from the
// pinned image without teaching Relay to parse ceremony documents itself.
func (d *dockerDriver) inspectionRunner(executable string, args ...string) ([]byte, []byte, error) {
	if executable != d.ceremonyBinary {
		return nil, nil, errors.New("Docker inspection requested an unexpected ceremony binary")
	}
	rewritten, mounts, err := d.rewriteReadOnlyArgs(args)
	if err != nil {
		return nil, nil, err
	}
	command := d.baseRunArgs(true, mounts)
	command = append(command, d.image)
	command = append(command, rewritten...)
	return d.client.Output(command...)
}

func (d *dockerDriver) inspector() transcript.Inspector {
	return transcript.Inspector{
		Executable: d.ceremonyBinary, CeremonyPath: d.definition,
		CeremonySignaturePath: d.definitionSig, CoordinatorPublicKeyPath: d.coordinatorKey,
		TranscriptRoot: d.root, Runner: d.inspectionRunner,
	}
}

func (d *dockerDriver) preflight() error {
	if os.Getuid() == 0 {
		return errors.New("Relay refuses to launch the contributor as root")
	}
	if _, err := d.swapStatus(); err != nil {
		return err
	}
	stdout, stderr, err := d.client.Output("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", d.image)
	if err != nil {
		return fmt.Errorf("pinned Docker image is not locally available (Relay never pulls it during a turn): %s", dockerDiagnostic(stderr, err))
	}
	if got := strings.TrimSpace(string(stdout)); got != d.platform {
		return fmt.Errorf("Docker image platform is %q, want %q", got, d.platform)
	}
	return nil
}

func (d *dockerDriver) contribution(o roleOpts, pos position, contributedAt time.Time) (*dockerLifecycleReceipt, error) {
	if err := d.preflight(); err != nil {
		return nil, err
	}
	if err := d.cleanupOrphan(); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(d.candidateRoot); err != nil {
		return nil, fmt.Errorf("candidate parent: %w", err)
	}
	handoff, err := os.MkdirTemp(d.candidateRoot, ".relay-handoff-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(handoff, 0o700); err != nil {
		_ = os.RemoveAll(handoff)
		return nil, err
	}

	receipt := &dockerLifecycleReceipt{
		Schema: dockerLifecycleSchema, ExecutionMode: dockerExecutionMode,
		Image: d.image, Platform: d.platform, CeremonyBinary: d.ceremonyBinary,
		CreatedAt: d.now().UTC().Format(time.RFC3339),
	}
	receipt.HostSwapStatus, err = d.swapStatus()
	if err != nil {
		_ = os.RemoveAll(handoff)
		return nil, err
	}
	receipt.CeremonyBinarySHA256, err = signedCeremonyBinarySHA256(d.definition, d.platform)
	if err != nil {
		_ = os.RemoveAll(handoff)
		return nil, err
	}
	containerOutput := "/relay/output/candidate"
	args, mounts, err := d.contributionArgs(o, pos, contributedAt, handoff, containerOutput)
	if err != nil {
		_ = os.RemoveAll(handoff)
		return nil, err
	}
	createArgs := d.baseCreateArgs(mounts)
	createArgs = append(createArgs,
		"--label", "org.zksecurity.relay.role=participant-contributor",
		d.image,
	)
	createArgs = append(createArgs, args...)
	stdout, stderr, err := d.client.Output(createArgs...)
	if err != nil {
		_ = os.RemoveAll(handoff)
		return nil, fmt.Errorf("create contributor container: %s", dockerDiagnostic(stderr, err))
	}
	containerID := strings.TrimSpace(string(stdout))
	if !validContainerID(containerID) {
		_ = os.RemoveAll(handoff)
		return nil, errors.New("Docker returned an invalid contributor container ID")
	}
	receipt.ContainerID = containerID
	state := dockerActiveState{
		Schema: dockerActiveStateSchema, ContainerID: containerID, Image: d.image,
		Platform: d.platform, HandoffDir: handoff, CreatedAt: receipt.CreatedAt,
	}
	if err := writeJSONNoReplace(d.activeStatePath(), state, 0o600); err != nil {
		_ = d.removeAndVerify(containerID)
		_ = os.RemoveAll(handoff)
		return nil, fmt.Errorf("persist contributor cleanup state: %w", err)
	}

	removed := false
	promoted := false
	defer func() {
		if !removed {
			_ = d.removeAndVerify(containerID)
		}
		if !promoted {
			_ = os.RemoveAll(handoff)
		}
	}()
	facts, err := d.inspectSecurity(containerID, mounts)
	if err != nil {
		return nil, err
	}
	receipt.Security = facts
	receipt.StartedAt = d.now().UTC().Format(time.RFC3339)
	startErr := d.client.Attached(os.Stdout, os.Stderr, "start", "--attach", containerID)
	receipt.ExitedAt = d.now().UTC().Format(time.RFC3339)
	exitCode, exitErr := d.exitCode(containerID)
	if exitErr != nil {
		return nil, exitErr
	}
	receipt.ExitCode = exitCode
	if err := d.removeAndVerify(containerID); err != nil {
		return nil, err
	}
	removed = true
	receipt.RemovedAt = d.now().UTC().Format(time.RFC3339)
	receipt.RemovalVerified = true
	if err := os.Remove(d.activeStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove contributor cleanup state: %w", err)
	}
	if startErr != nil || exitCode != 0 {
		_ = os.RemoveAll(handoff)
		if startErr != nil {
			return nil, fmt.Errorf("contribution container failed with exit code %d: %w", exitCode, startErr)
		}
		return nil, fmt.Errorf("contribution container exited with status %d", exitCode)
	}

	publicCandidate := filepath.Join(handoff, "candidate")
	if err := validateContributionHandoff(publicCandidate); err != nil {
		_ = os.RemoveAll(handoff)
		return nil, err
	}
	if _, err := os.Lstat(o.outDir); err == nil || !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll(handoff)
		if err == nil {
			return nil, fmt.Errorf("candidate output already exists: %s", o.outDir)
		}
		return nil, err
	}
	if err := os.Rename(publicCandidate, o.outDir); err != nil {
		_ = os.RemoveAll(handoff)
		return nil, fmt.Errorf("promote verified public handoff: %w", err)
	}
	if err := os.Remove(handoff); err != nil {
		return nil, fmt.Errorf("remove empty handoff directory: %w", err)
	}
	promoted = true
	return receipt, nil
}

func (d *dockerDriver) attestErasure(o roleOpts, destroyedAt time.Time) error {
	args := []string{o.phase, "attest-erasure",
		"--ceremony", d.definition,
		"--ceremony-signature", d.definitionSig,
		"--coordinator-public-key-file", d.coordinatorKey,
		"--participant-id", o.role,
		"--participant-signing-key", d.signingKey,
		"--candidate-dir", o.outDir,
		"--destroyed-at", destroyedAt.UTC().Format(time.RFC3339),
	}
	rewritten, mounts, err := d.rewriteArgs(args, map[string]string{o.outDir: "/relay/output/candidate"})
	if err != nil {
		return err
	}
	for i := range mounts {
		if mounts[i].Source == o.outDir {
			mounts[i].ReadOnly = false
		}
	}
	command := d.baseRunArgs(true, mounts)
	command = append(command, d.image)
	command = append(command, rewritten...)
	return d.client.Attached(os.Stdout, os.Stderr, command...)
}

// attestHostWipe creates only public, participant-signed evidence. It runs
// after the whole Mac has been erased and cleanly reinstalled, so it does not
// share the contributor container's lifecycle or generate toxic waste.
func (d *dockerDriver) attestHostWipe(o roleOpts, wipedAt time.Time, outDir string) error {
	if err := d.preflight(); err != nil {
		return err
	}
	if _, err := os.Lstat(outDir); err == nil {
		return fmt.Errorf("host-wipe output already exists: %s", outDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(outDir)
	if err := ensurePrivateDirectory(parent); err != nil {
		return fmt.Errorf("host-wipe output parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".relay-host-wipe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	containerOut := "/relay/output/evidence"
	args := []string{"ops", "attest-host-wipe",
		"--ceremony", "/relay/trust/ceremony.json",
		"--ceremony-signature", "/relay/trust/ceremony.sig",
		"--coordinator-public-key-file", "/relay/trust/coordinator.hex",
		"--participant-id", o.role,
		"--participant-signing-key", "/relay/key/participant.key",
		"--wiped-at", wipedAt.UTC().Format(time.RFC3339),
		"--out-dir", containerOut,
	}
	mounts := []dockerMount{
		{Source: d.definition, Destination: "/relay/trust/ceremony.json", ReadOnly: true},
		{Source: d.definitionSig, Destination: "/relay/trust/ceremony.sig", ReadOnly: true},
		{Source: d.coordinatorKey, Destination: "/relay/trust/coordinator.hex", ReadOnly: true},
		{Source: d.signingKey, Destination: "/relay/key/participant.key", ReadOnly: true},
		{Source: staging, Destination: "/relay/output", ReadOnly: false},
	}
	if err := validateMountSources(mounts); err != nil {
		return err
	}
	command := d.baseRunArgs(true, mounts)
	command = append(command, d.image)
	command = append(command, args...)
	if err := d.client.Attached(os.Stdout, os.Stderr, command...); err != nil {
		return fmt.Errorf("create host-wipe attestation in Docker: %w", err)
	}
	evidence := filepath.Join(staging, "evidence")
	if err := validateHostWipeHandoff(evidence); err != nil {
		return err
	}
	if err := os.Rename(evidence, outDir); err != nil {
		return fmt.Errorf("promote host-wipe evidence: %w", err)
	}
	return nil
}

func validateHostWipeHandoff(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read host-wipe evidence handoff: %w", err)
	}
	wanted := map[string]bool{"host-wipe.json": false, "host-wipe.sig": false}
	if len(entries) != len(wanted) {
		return fmt.Errorf("host-wipe evidence contains %d entries, want exactly %d", len(entries), len(wanted))
	}
	for _, entry := range entries {
		seen, ok := wanted[entry.Name()]
		if !ok || seen || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected host-wipe evidence entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("host-wipe evidence entry %q is not a regular file", entry.Name())
		}
		wanted[entry.Name()] = true
	}
	return nil
}

func (d *dockerDriver) contributionArgs(o roleOpts, pos position, contributedAt time.Time, handoff, output string) ([]string, []dockerMount, error) {
	container := o
	container.root = "/relay/input"
	container.definition = "/relay/trust/ceremony.json"
	container.definitionSig = "/relay/trust/ceremony.sig"
	container.coordinatorKey = "/relay/trust/coordinator.hex"
	container.signingKey = "/relay/key/participant.key"
	container.envPath = "/relay/config/environment.json"
	container.outDir = output
	chain, err := pathWithin(d.root, pos.chainPath, "/relay/input")
	if err != nil {
		return nil, nil, fmt.Errorf("chain path: %w", err)
	}
	containerPos := pos
	containerPos.chainPath = chain
	if pos.chain.ChainSignaturePath != "" {
		chainSig, err := pathWithin(d.root, pos.chain.ChainSignaturePath, "/relay/input")
		if err != nil {
			return nil, nil, fmt.Errorf("chain signature path: %w", err)
		}
		containerPos.chain.ChainSignaturePath = chainSig
	}
	args := contributionCommandArgs(container, containerPos, contributedAt)
	mounts := []dockerMount{
		{Source: d.root, Destination: "/relay/input", ReadOnly: true},
		{Source: d.definition, Destination: container.definition, ReadOnly: true},
		{Source: d.definitionSig, Destination: container.definitionSig, ReadOnly: true},
		{Source: d.coordinatorKey, Destination: container.coordinatorKey, ReadOnly: true},
		{Source: d.signingKey, Destination: container.signingKey, ReadOnly: true},
		{Source: d.environment, Destination: container.envPath, ReadOnly: true},
		{Source: handoff, Destination: "/relay/output", ReadOnly: false},
	}
	if err := validateMountSources(mounts); err != nil {
		return nil, nil, err
	}
	return args, mounts, nil
}

func (d *dockerDriver) rewriteReadOnlyArgs(args []string) ([]string, []dockerMount, error) {
	return d.rewriteArgs(args, nil)
}

func (d *dockerDriver) rewriteArgs(args []string, writable map[string]string) ([]string, []dockerMount, error) {
	exact := map[string]string{
		d.definition: "/relay/trust/ceremony.json", d.definitionSig: "/relay/trust/ceremony.sig",
		d.coordinatorKey: "/relay/trust/coordinator.hex", d.signingKey: "/relay/key/participant.key",
		d.environment: "/relay/config/environment.json",
	}
	for host, container := range writable {
		exact[host] = container
	}
	rewritten := append([]string(nil), args...)
	mountBySource := make(map[string]dockerMount)
	for i, arg := range rewritten {
		if mapped, ok := exact[arg]; ok && arg != "" {
			rewritten[i] = mapped
			mountBySource[arg] = dockerMount{Source: arg, Destination: mapped, ReadOnly: writable[arg] == ""}
			continue
		}
		if filepath.IsAbs(arg) {
			mapped, err := pathWithin(d.root, arg, "/relay/input")
			if err != nil {
				return nil, nil, fmt.Errorf("refuse unrecognized host path %q in Docker ceremony command", arg)
			}
			rewritten[i] = mapped
			mountBySource[d.root] = dockerMount{Source: d.root, Destination: "/relay/input", ReadOnly: true}
		}
	}
	mounts := make([]dockerMount, 0, len(mountBySource))
	for _, mount := range mountBySource {
		mounts = append(mounts, mount)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Destination < mounts[j].Destination })
	if err := validateMountSources(mounts); err != nil {
		return nil, nil, err
	}
	return rewritten, mounts, nil
}

func (d *dockerDriver) baseRunArgs(remove bool, mounts []dockerMount) []string {
	args := []string{"run"}
	if remove {
		args = append(args, "--rm")
	}
	return append(args, d.securityArgs(mounts)...)
}

func (d *dockerDriver) baseCreateArgs(mounts []dockerMount) []string {
	return append([]string{"create"}, d.securityArgs(mounts)...)
}

func (d *dockerDriver) securityArgs(mounts []dockerMount) []string {
	uid, gid := os.Getuid(), os.Getgid()
	args := []string{
		"--pull", "never", "--platform", d.platform,
		"--entrypoint", d.ceremonyBinary,
		"--network", "none", "--read-only",
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
		"--ulimit", "core=0:0", "--pids-limit", "256",
		"--ipc", "none", "--log-driver", "none",
		"--env", "HOME=/nonexistent",
		"--workdir", "/tmp",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=700",
	}
	for _, mount := range mounts {
		value := "type=bind,src=" + mount.Source + ",dst=" + mount.Destination
		if mount.ReadOnly {
			value += ",readonly"
		}
		args = append(args, "--mount", value)
	}
	return args
}

func (d *dockerDriver) inspectSecurity(containerID string, expected []dockerMount) (dockerSecurityFacts, error) {
	stdout, stderr, err := d.client.Output("inspect", containerID)
	if err != nil {
		return dockerSecurityFacts{}, fmt.Errorf("inspect contributor container: %s", dockerDiagnostic(stderr, err))
	}
	var records []struct {
		Config struct {
			Image string `json:"Image"`
			User  string `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string   `json:"NetworkMode"`
			ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
			Privileged     bool     `json:"Privileged"`
			CapDrop        []string `json:"CapDrop"`
			SecurityOpt    []string `json:"SecurityOpt"`
			PidMode        string   `json:"PidMode"`
			IpcMode        string   `json:"IpcMode"`
			UsernsMode     string   `json:"UsernsMode"`
			ReadonlyPaths  []string `json:"ReadonlyPaths"`
			LogConfig      struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
			Tmpfs   map[string]string `json:"Tmpfs"`
			Ulimits []struct {
				Name string `json:"Name"`
				Soft int64  `json:"Soft"`
				Hard int64  `json:"Hard"`
			} `json:"Ulimits"`
			Mounts []struct {
				Type     string `json:"Type"`
				Source   string `json:"Source"`
				Target   string `json:"Target"`
				ReadOnly bool   `json:"ReadOnly"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if err := json.Unmarshal(stdout, &records); err != nil || len(records) != 1 {
		return dockerSecurityFacts{}, errors.New("decode contributor Docker inspection")
	}
	r := records[0]
	facts := dockerSecurityFacts{
		NetworkNone: r.HostConfig.NetworkMode == "none", ReadOnlyRoot: r.HostConfig.ReadonlyRootfs,
		NonRoot:         r.Config.User != "" && r.Config.User != "0" && r.Config.User != "root" && !strings.HasPrefix(r.Config.User, "0:"),
		CapabilitiesOff: stringSliceContainsFold(r.HostConfig.CapDrop, "ALL"),
		NoNewPrivileges: stringSliceContainsPrefix(r.HostConfig.SecurityOpt, "no-new-privileges"),
		LogDriverOff:    r.HostConfig.LogConfig.Type == "none",
		PrivatePID:      r.HostConfig.PidMode != "host", PrivateIPC: r.HostConfig.IpcMode != "host",
		NoHostUserNS: r.HostConfig.UsernsMode != "host",
	}
	for _, limit := range r.HostConfig.Ulimits {
		if limit.Name == "core" && limit.Soft == 0 && limit.Hard == 0 {
			facts.CoreDumpsOff = true
		}
	}
	tmpfs := r.HostConfig.Tmpfs["/tmp"]
	facts.BoundedTmpfs = strings.Contains(tmpfs, "size=67108864") && strings.Contains(tmpfs, "noexec") && strings.Contains(tmpfs, "nosuid") && strings.Contains(tmpfs, "nodev")
	facts.MountsVerified = verifiedMounts(r.HostConfig.Mounts, expected) && verifiedRuntimeMounts(r.Mounts, expected)
	if r.Config.Image != d.image || r.HostConfig.Privileged ||
		!facts.NetworkNone || !facts.ReadOnlyRoot || !facts.NonRoot || !facts.CapabilitiesOff ||
		!facts.NoNewPrivileges || !facts.CoreDumpsOff || !facts.LogDriverOff ||
		!facts.PrivatePID || !facts.PrivateIPC || !facts.NoHostUserNS || !facts.BoundedTmpfs || !facts.MountsVerified {
		return dockerSecurityFacts{}, errors.New("effective contributor container configuration failed isolation verification")
	}
	return facts, nil
}

func verifiedMounts(actual []struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
}, expected []dockerMount) bool {
	if len(actual) != len(expected) {
		return false
	}
	want := make(map[string]dockerMount, len(expected))
	for _, mount := range expected {
		want[mount.Destination] = mount
	}
	for _, mount := range actual {
		expectedMount, ok := want[mount.Target]
		if !ok || mount.Type != "bind" || filepath.Clean(mount.Source) != expectedMount.Source || mount.ReadOnly != expectedMount.ReadOnly {
			return false
		}
	}
	return true
}

func verifiedRuntimeMounts(actual []struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}, expected []dockerMount) bool {
	if len(actual) != len(expected) {
		return false
	}
	want := make(map[string]dockerMount, len(expected))
	for _, mount := range expected {
		want[mount.Destination] = mount
	}
	for _, mount := range actual {
		expectedMount, ok := want[mount.Destination]
		if !ok || mount.Type != "bind" || filepath.Clean(mount.Source) != expectedMount.Source || mount.RW == expectedMount.ReadOnly {
			return false
		}
	}
	return true
}

func (d *dockerDriver) exitCode(containerID string) (int, error) {
	stdout, stderr, err := d.client.Output("inspect", "--format", "{{.State.ExitCode}}", containerID)
	if err != nil {
		return 0, fmt.Errorf("inspect contributor exit status: %s", dockerDiagnostic(stderr, err))
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(stdout)))
	if err != nil {
		return 0, errors.New("Docker returned an invalid contributor exit status")
	}
	return code, nil
}

func (d *dockerDriver) removeAndVerify(containerID string) error {
	if !validContainerID(containerID) {
		return errors.New("refuse to remove an invalid Docker container ID")
	}
	_, removeStderr, removeErr := d.client.Output("rm", "--force", "--volumes", containerID)
	if _, _, err := d.client.Output("inspect", containerID); err == nil {
		return errors.New("contributor container still exists after removal")
	}
	stdout, stderr, err := d.client.Output("container", "ls", "--all", "--no-trunc", "--filter", "id="+containerID, "--format", "{{.ID}}")
	if err != nil {
		return fmt.Errorf("verify contributor absence: %s", dockerDiagnostic(stderr, err))
	}
	if strings.TrimSpace(string(stdout)) != "" {
		return errors.New("contributor container still appears in Docker after removal")
	}
	if removeErr != nil && !strings.Contains(strings.ToLower(string(removeStderr)), "no such container") {
		return fmt.Errorf("remove contributor container: %s", dockerDiagnostic(removeStderr, removeErr))
	}
	return nil
}

func (d *dockerDriver) cleanupOrphan() error {
	path := d.activeStatePath()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read recorded contributor cleanup state: %w", err)
	}
	var state dockerActiveState
	if err := json.Unmarshal(raw, &state); err != nil || state.Schema != dockerActiveStateSchema || !validContainerID(state.ContainerID) {
		return errors.New("recorded contributor cleanup state is invalid; refusing to start another contribution")
	}
	if err := d.removeAndVerify(state.ContainerID); err != nil {
		return fmt.Errorf("clean recorded contributor before continuing: %w", err)
	}
	if safeHandoffPath(d.candidateRoot, state.HandoffDir) {
		_ = os.RemoveAll(state.HandoffDir)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed recorded contributor container %s before continuing\n", shortContainerID(state.ContainerID))
	return nil
}

func (d *dockerDriver) activeStatePath() string {
	return filepath.Join(d.candidateRoot, dockerActiveStateFileName)
}

func validateContributionHandoff(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("contributor did not produce a safe public candidate directory")
	}
	want := map[string]bool{"contribution.bin": true, "attestation.json": true, "attestation.sig": true}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != len(want) {
		return errors.New("contributor public handoff contains unexpected files")
	}
	for _, entry := range entries {
		if !want[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("contributor public handoff contains unexpected entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("contributor public handoff entry %q is not a regular file", entry.Name())
		}
	}
	return nil
}

func validateMountSources(mounts []dockerMount) error {
	seenDestination := make(map[string]bool, len(mounts))
	for i := range mounts {
		if strings.ContainsAny(mounts[i].Source, ",\x00") || strings.ContainsAny(mounts[i].Destination, ",\x00") {
			return errors.New("Docker mount paths must not contain commas or NUL bytes")
		}
		if !filepath.IsAbs(mounts[i].Source) || filepath.Clean(mounts[i].Source) != mounts[i].Source ||
			!filepath.IsAbs(mounts[i].Destination) || filepath.Clean(mounts[i].Destination) != mounts[i].Destination {
			return errors.New("Docker mount paths must be absolute and clean")
		}
		if seenDestination[mounts[i].Destination] {
			return fmt.Errorf("duplicate Docker mount destination %s", mounts[i].Destination)
		}
		seenDestination[mounts[i].Destination] = true
		info, err := os.Lstat(mounts[i].Source)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Docker mount source is missing or is a symlink: %s", mounts[i].Source)
		}
		resolved, err := filepath.EvalSymlinks(mounts[i].Source)
		if err != nil {
			return fmt.Errorf("resolve Docker mount source: %s", mounts[i].Source)
		}
		// Resolve symlinks in ancestor directories once, before container
		// creation. The source itself was checked with Lstat above, so this
		// handles platform paths such as macOS /var -> /private/var without
		// accepting a symlink as the mounted file or directory.
		mounts[i].Source = filepath.Clean(resolved)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory must not be accessible by group or other users")
	}
	return nil
}

func pathWithin(root, hostPath, containerRoot string) (string, error) {
	relative, err := filepath.Rel(root, hostPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("path is outside the authenticated input root")
	}
	return filepath.ToSlash(filepath.Join(containerRoot, relative)), nil
}

func validContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func signedCeremonyBinarySHA256(path, platform string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read signed ceremony software binding: %w", err)
	}
	var definition struct {
		Schema   string `json:"schema"`
		Software struct {
			GoOS       string `json:"goos"`
			GoArch     string `json:"goarch"`
			ToolBinary struct {
				SHA256 string `json:"sha256"`
			} `json:"tool_binary"`
			Binaries []struct {
				GoOS       string `json:"goos"`
				GoArch     string `json:"goarch"`
				ToolBinary struct {
					SHA256 string `json:"sha256"`
				} `json:"tool_binary"`
			} `json:"binaries"`
		} `json:"software"`
	}
	if err := json.Unmarshal(raw, &definition); err != nil {
		return "", fmt.Errorf("decode signed ceremony software binding: %w", err)
	}
	var digest string
	switch definition.Schema {
	case "proof-tool-mpc-ceremony-definition-v1":
		if definition.Software.GoOS+"/"+definition.Software.GoArch != platform {
			return "", fmt.Errorf(
				"signed ceremony binary platform is %q, want configured Docker platform %q",
				definition.Software.GoOS+"/"+definition.Software.GoArch,
				platform,
			)
		}
		digest = definition.Software.ToolBinary.SHA256
	case "proof-tool-mpc-ceremony-definition-v2":
		for _, binary := range definition.Software.Binaries {
			if binary.GoOS+"/"+binary.GoArch != platform {
				continue
			}
			if digest != "" {
				return "", fmt.Errorf("signed ceremony definition contains multiple binaries for %s", platform)
			}
			digest = binary.ToolBinary.SHA256
		}
		if digest == "" {
			return "", fmt.Errorf("signed ceremony definition allows no binary for %s", platform)
		}
	default:
		return "", fmt.Errorf("unsupported signed ceremony definition schema %q", definition.Schema)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return "", errors.New("signed ceremony definition has no valid tool binary SHA-256")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		return "", errors.New("signed ceremony definition has an invalid tool binary SHA-256")
	}
	return digest, nil
}

func dockerHostSwapStatus() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return "not-assessed-macos-host-wipe-required", nil
	case "linux":
		raw, err := os.ReadFile("/proc/swaps")
		if err != nil {
			return "", fmt.Errorf("check host swap: %w", err)
		}
		if len(strings.Fields(string(raw))) > 5 {
			return "", errors.New("host swap is active; disable it before creating a contributor container")
		}
		return "disabled", nil
	default:
		return "", fmt.Errorf("Docker participant execution is unsupported on %s", runtime.GOOS)
	}
}

func (d *dockerDriver) swapStatus() (string, error) {
	if d.hostSwapStatus != nil {
		return d.hostSwapStatus()
	}
	return dockerHostSwapStatus()
}

func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func safeHandoffPath(parent, candidate string) bool {
	return filepath.Dir(candidate) == parent && strings.HasPrefix(filepath.Base(candidate), ".relay-handoff-")
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".relay-json-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func verifiedLifecycleFacts(f dockerSecurityFacts) bool {
	return f.NetworkNone && f.ReadOnlyRoot && f.NonRoot && f.CapabilitiesOff &&
		f.NoNewPrivileges && f.CoreDumpsOff && f.LogDriverOff && f.PrivatePID &&
		f.PrivateIPC && f.NoHostUserNS && f.BoundedTmpfs && f.MountsVerified
}

func stringSliceContainsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func stringSliceContainsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func dockerDiagnostic(stderr []byte, err error) string {
	if message := strings.TrimSpace(string(stderr)); message != "" {
		return message
	}
	return err.Error()
}
