package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type dockerClientFake struct {
	capacityContainers []dockerCapacityContainer
	image              string
	platform           string
	createArgs         []string
	handoff            string
	removed            bool
	stillPresent       bool
	unsafe             bool
	unsafeResource     string
	onCreate           func()
	createErrAfter     bool
	host               string
	endpoint           string
	daemonID           string
	usernsMode         string
	securityOptions    []string
	onAttachedContext  func(context.Context) error
	attachDelay        time.Duration
}

func (f *dockerClientFake) Output(args ...string) ([]byte, []byte, error) {
	if len(args) == 2 && args[0] == "inspect" {
		for _, c := range f.capacityContainers {
			if c.ID == args[1] {
				raw, _ := json.Marshal([]dockerCapacityContainer{c})
				return raw, nil, nil
			}
		}
	}
	if len(args) == 6 && strings.Join(args, " ") == "container ls --all --no-trunc --format {{.ID}}" {
		var ids []string
		for _, c := range f.capacityContainers {
			ids = append(ids, c.ID)
		}
		return []byte(strings.Join(ids, "\n")), nil, nil
	}

	switch {
	case len(args) == 2 && args[0] == "context" && args[1] == "show":
		return []byte("test-local\n"), nil, nil
	case len(args) >= 3 && args[0] == "context" && args[1] == "inspect":
		endpoint := f.endpoint
		if endpoint == "" {
			endpoint = "unix:///var/run/docker.sock"
		}
		raw, _ := json.Marshal(endpoint)
		return append(raw, '\n'), nil, nil
	case len(args) >= 1 && args[0] == "info":
		daemonID := f.daemonID
		if daemonID == "" {
			daemonID = "test-daemon-id"
		}
		raw, _ := json.Marshal(map[string]any{
			"ID": daemonID, "Name": "test-daemon", "ServerVersion": "28.0.0",
			"OperatingSystem": "Test Linux", "OSType": "linux", "Architecture": "arm64",
			"SecurityOptions": f.securityOptions, "MemoryLimit": true, "SwapLimit": true,
			"CpuCfsQuota": true, "MemTotal": int64(16) << 30, "NCPU": 8,
		})
		return raw, nil, nil
	case len(args) >= 2 && args[0] == "image" && args[1] == "inspect":
		return []byte(f.platform + "\n"), nil, nil
	case len(args) > 0 && args[0] == "create":
		f.createArgs = append([]string(nil), args...)
		for index, arg := range args {
			if arg != "--mount" || index+1 >= len(args) {
				continue
			}
			parts := strings.Split(args[index+1], ",")
			var source, destination string
			for _, part := range parts {
				if strings.HasPrefix(part, "src=") {
					source = strings.TrimPrefix(part, "src=")
				}
				if strings.HasPrefix(part, "dst=") {
					destination = strings.TrimPrefix(part, "dst=")
				}
			}
			if destination == "/relay/output" {
				f.handoff = source
			}
		}
		if f.onCreate != nil {
			f.onCreate()
		}
		if f.createErrAfter {
			return nil, []byte("lost create response"), errors.New("transport closed")
		}
		return []byte(testContainerID + "\n"), nil, nil
	case len(args) == 2 && args[0] == "inspect":
		if f.removed && !f.stillPresent {
			return nil, []byte("No such container"), errors.New("exit status 1")
		}
		return f.inspectionJSON(), nil, nil
	case len(args) == 4 && args[0] == "inspect" && args[1] == "--format" && args[2] == "{{.Id}}":
		if f.removed && !f.stillPresent {
			return nil, []byte("No such container"), errors.New("exit status 1")
		}
		return []byte(testContainerID + "\n"), nil, nil
	case len(args) >= 3 && args[0] == "inspect" && args[1] == "--format":
		return []byte("0\n"), nil, nil
	case len(args) > 0 && args[0] == "rm":
		f.removed = true
		return []byte(testContainerID + "\n"), nil, nil
	case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
		if f.stillPresent {
			return []byte(testContainerID + "\n"), nil, nil
		}
		return nil, nil, nil
	default:
		return nil, nil, errors.New("unexpected fake Docker command: " + strings.Join(args, " "))
	}
}

func (f *dockerClientFake) Attached(_ io.Writer, _ io.Writer, args ...string) error {
	return f.AttachedContext(context.Background(), io.Discard, io.Discard, args...)
}

func (f *dockerClientFake) AttachedContext(ctx context.Context, _ io.Writer, _ io.Writer, args ...string) error {
	if len(args) != 3 || args[0] != "start" || args[1] != "--attach" || args[2] != testContainerID {
		return errors.New("unexpected attached Docker command")
	}
	if f.onAttachedContext != nil {
		return f.onAttachedContext(ctx)
	}
	if f.attachDelay > 0 {
		select {
		case <-time.After(f.attachDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	candidate := filepath.Join(f.handoff, "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"contribution.bin", "attestation.json", "attestation.sig"} {
		if err := os.WriteFile(filepath.Join(candidate, name), []byte("public "+name), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (f *dockerClientFake) BindHost(host string) dockerCommandClient {
	f.host = host
	return f
}

func (f *dockerClientFake) inspectionJSON() []byte {
	user := "1000:1000"
	image := f.image
	network := "none"
	if f.unsafe {
		network = "bridge"
	}
	var mounts []map[string]any
	var runtimeMounts []map[string]any
	name := ""
	labels := map[string]string{}
	var environment []string
	var memory, memorySwap, nanoCPUs int64
	for index, arg := range f.createArgs {
		if arg == "--name" && index+1 < len(f.createArgs) {
			name = f.createArgs[index+1]
		}
		if arg == "--label" && index+1 < len(f.createArgs) {
			key, value, ok := strings.Cut(f.createArgs[index+1], "=")
			if ok {
				labels[key] = value
			}
		}
		if arg == "--user" && index+1 < len(f.createArgs) {
			user = f.createArgs[index+1]
		}
		if arg == "--env" && index+1 < len(f.createArgs) {
			environment = append(environment, f.createArgs[index+1])
		}
		if arg == "--memory" && index+1 < len(f.createArgs) {
			value := strings.TrimSuffix(f.createArgs[index+1], "g")
			gib, _ := strconv.ParseInt(value, 10, 64)
			memory = gib << 30
		}
		if arg == "--memory-swap" && index+1 < len(f.createArgs) {
			value := strings.TrimSuffix(f.createArgs[index+1], "g")
			gib, _ := strconv.ParseInt(value, 10, 64)
			memorySwap = gib << 30
		}
		if arg == "--cpus" && index+1 < len(f.createArgs) {
			cpus, _ := strconv.ParseInt(f.createArgs[index+1], 10, 64)
			nanoCPUs = cpus * 1_000_000_000
		}
		if arg != "--mount" || index+1 >= len(f.createArgs) {
			continue
		}
		mount := map[string]any{"Type": "bind"}
		for _, part := range strings.Split(f.createArgs[index+1], ",") {
			switch {
			case strings.HasPrefix(part, "src="):
				mount["Source"] = strings.TrimPrefix(part, "src=")
			case strings.HasPrefix(part, "dst="):
				mount["Target"] = strings.TrimPrefix(part, "dst=")
			case part == "readonly":
				mount["ReadOnly"] = true
			}
		}
		if _, ok := mount["ReadOnly"]; !ok {
			mount["ReadOnly"] = false
		}
		mounts = append(mounts, mount)
		runtimeMounts = append(runtimeMounts, map[string]any{
			"Type": mount["Type"], "Source": mount["Source"], "Destination": mount["Target"],
			"RW": !mount["ReadOnly"].(bool),
		})
	}
	switch f.unsafeResource {
	case "memory":
		memory = 0
	case "memory-swap":
		memorySwap = -1
	case "cpu":
		nanoCPUs = 0
	case "environment":
		environment = append(environment, "GOMEMLIMIT=unlimited")
	}
	record := []map[string]any{{
		"Name":   "/" + name,
		"Config": map[string]any{"Image": image, "User": user, "Labels": labels, "Env": environment},
		"HostConfig": map[string]any{
			"NetworkMode": network, "ReadonlyRootfs": true, "Privileged": false,
			"Memory": memory, "MemorySwap": memorySwap, "NanoCpus": nanoCPUs,
			"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges=true"},
			"PidMode": "", "IpcMode": "none", "UsernsMode": f.usernsMode,
			"LogConfig": map[string]any{"Type": "none"},
			"Tmpfs":     map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=700"},
			"Ulimits":   []map[string]any{{"Name": "core", "Soft": 0, "Hard": 0}},
			"Mounts":    mounts,
		},
		"Mounts": runtimeMounts,
	}}
	raw, _ := json.Marshal(record)
	return raw
}

func TestDockerContributionMapsExplicitPhase1Seal(t *testing.T) {
	o, pos, driver, _ := dockerContributionFixture(t)
	o.phase = "phase2"
	o.phase1Seal = filepath.Join(driver.root, "phase1", "sealed", "seal.json")
	o.phase1SealSig = filepath.Join(driver.root, "phase1", "sealed", "seal.sig")
	args, _, err := driver.contributionArgs(o, pos, time.Now(), driver.candidateRoot, "/relay/output/candidate")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, path := range []string{"/relay/input/phase1/sealed/seal.json", "/relay/input/phase1/sealed/seal.sig"} {
		if !strings.Contains(joined, path) {
			t.Fatal("seal not mapped", args)
		}
	}
	if strings.Contains(joined, driver.root) {
		t.Fatal("host path leaked into container argv")
	}
	o.phase1Seal = filepath.Join(t.TempDir(), "outside-seal.json")
	if _, _, err := driver.contributionArgs(o, pos, time.Now(), driver.candidateRoot, "/relay/output/candidate"); err == nil {
		t.Fatal("accepted seal outside read-only transcript")
	}
}

func dockerContributionFixture(t *testing.T) (roleOpts, position, *dockerDriver, *dockerClientFake) {
	t.Helper()
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "")
	base := t.TempDir()
	root := filepath.Join(base, "public")
	candidates := filepath.Join(base, "candidates")
	secure := filepath.Join(base, "secure")
	for _, dir := range []string{root, candidates, secure, filepath.Join(root, "phase1")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := map[string]string{
		"definition":    filepath.Join(root, "ceremony.json"),
		"definitionSig": filepath.Join(root, "ceremony.sig"),
		"coordinator":   filepath.Join(secure, "coordinator.hex"),
		"key":           filepath.Join(secure, "participant.hex"),
		"environment":   filepath.Join(secure, "environment.json"),
		"chain":         filepath.Join(root, "phase1", "chain.json"),
		"chainSig":      filepath.Join(root, "phase1", "chain.sig"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	definition := `{"schema":"proof-tool-mpc-ceremony-definition-v2","software":{"binaries":[{"goos":"linux","goarch":"arm64","goarm64":"v8.0","tool_binary":{"sha256":"sha256:` + strings.Repeat("c", 64) + `"}}]}}`
	if err := os.WriteFile(paths["definition"], []byte(definition), 0o600); err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("b", 64)
	fake := &dockerClientFake{image: image, platform: "linux/arm64"}
	driver := &dockerDriver{
		image: image, platform: fake.platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony",
		root: root, definition: paths["definition"], definitionSig: paths["definitionSig"],
		coordinatorKey: paths["coordinator"], signingKey: paths["key"], environment: paths["environment"],
		candidateRoot: candidates, client: fake, now: time.Now,
		hostSwapStatus: func() (string, error) { return dockerLinuxSwapDisabled, nil },
	}
	o := roleOpts{
		root: root, definition: paths["definition"], definitionSig: paths["definitionSig"],
		coordinatorKey: paths["coordinator"], ceremonyBinary: driver.ceremonyBinary,
		phase: "phase1", role: "participant-01", signingKey: paths["key"], envPath: paths["environment"],
		outDir: filepath.Join(candidates, "phase1-0001-attempt"), docker: driver,
	}
	pos := position{
		chainPath: paths["chain"], nextIndex: 1,
		chain: transcript.Chain{ChainSignaturePath: paths["chainSig"]},
	}
	return o, pos, driver, fake
}

func TestDockerContributionRemovesContainerBeforePromotingPublicOutput(t *testing.T) {
	o, pos, _, fake := dockerContributionFixture(t)
	o.operationID = strings.Repeat("d", 32)
	originalInterval, originalOutput := progressHeartbeatInterval, progressOutput
	t.Cleanup(func() {
		progressHeartbeatInterval = originalInterval
		progressOutput = originalOutput
	})
	progressHeartbeatInterval = time.Millisecond
	var progress bytes.Buffer
	progressOutput = &progress
	fake.attachDelay = 5 * time.Millisecond
	if err := runNextAt(o, pos, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"phase1 contribution computation: started",
		"phase1 contribution computation: still running",
		"phase1 contribution computation: completed",
	} {
		if !strings.Contains(progress.String(), want) {
			t.Fatalf("contribution progress missing %q:\n%s", want, progress.String())
		}
	}
	if !fake.removed {
		t.Fatal("contributor container was not removed")
	}
	for _, name := range []string{"contribution.bin", "attestation.json", "attestation.sig", dockerLifecycleLogName} {
		if info, err := os.Lstat(filepath.Join(o.outDir, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("public output %s was not promoted safely: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(o.outDir), dockerActiveStateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active container state remains after cleanup: %v", err)
	}
	if fake.host != "unix:///var/run/docker.sock" {
		t.Fatalf("Docker commands were not pinned to the inspected endpoint: %q", fake.host)
	}
	create := strings.Join(fake.createArgs, " ")
	if !strings.Contains(create, "--name relay-contributor-"+o.operationID) || !strings.Contains(create, "org.zksecurity.relay.operation="+o.operationID) {
		t.Fatalf("contributor did not use the preallocated guided operation ID: %s", create)
	}
	raw, err := os.ReadFile(filepath.Join(o.outDir, dockerLifecycleLogName))
	if err != nil {
		t.Fatal(err)
	}
	var receipt dockerLifecycleReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Daemon.ID != "test-daemon-id" || !receipt.Daemon.LocalUnixEndpoint {
		t.Fatalf("daemon identity was not recorded: %#v", receipt.Daemon)
	}
}

func TestDockerInspectionMountsOnlyExactRequestedWorkFile(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "ceremony", "public")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(work, "my-enrollment", "canonical.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	driver := dockerDriver{root: root, inspectionRoot: work}
	rewritten, mounts, err := driver.rewriteReadOnlyArgs([]string{"--enrollment", record, "--same", record})
	if err != nil {
		t.Fatal(err)
	}
	resolvedRecord, err := filepath.EvalSymlinks(record)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten[1] != rewritten[3] || len(mounts) != 1 || mounts[0].Source != resolvedRecord || !mounts[0].ReadOnly {
		t.Fatalf("inspection exposed more than the exact requested file: args=%v mounts=%+v", rewritten, mounts)
	}
	if _, _, err := driver.rewriteReadOnlyArgs([]string{"--bad", work}); err == nil {
		t.Fatal("mounted the entire V4 work directory")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.rewriteReadOnlyArgs([]string{"--bad", outside}); err == nil {
		t.Fatal("mounted a path outside the V4 work directory")
	}
}

func TestDockerInspectionKeepsArtifactRootAndChildrenInOneMount(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "ceremony", "public")
	stage := filepath.Join(work, "sync", "artifacts")
	checkpoint := filepath.Join(stage, "checkpoints", "final", "checkpoint.json")
	if err := os.MkdirAll(filepath.Dir(checkpoint), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkpoint, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	driver := dockerDriver{root: root, inspectionRoot: work}
	// The checkpoint intentionally comes first: proof-tool command ordering must
	// not decide whether it remains below the explicit artifact root.
	rewritten, mounts, err := driver.rewriteReadOnlyArgs([]string{"--checkpoint", checkpoint, "--artifact-root", stage})
	if err != nil {
		t.Fatal(err)
	}
	resolvedStage, err := filepath.EvalSymlinks(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].Source != resolvedStage || !mounts[0].ReadOnly {
		t.Fatalf("artifact root was not mounted once read-only: %+v", mounts)
	}
	if want := "/relay/artifacts"; rewritten[3] != want {
		t.Fatalf("artifact root = %q, want %q", rewritten[3], want)
	}
	if want := "/relay/artifacts/checkpoints/final/checkpoint.json"; rewritten[1] != want {
		t.Fatalf("checkpoint escaped its artifact-root mount: got %q, want %q", rewritten[3], want)
	}
}

func TestDockerInspectionRejectsSymlinkUnderArtifactRoot(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "ceremony", "public")
	stage := filepath.Join(work, "sync", "artifacts")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(outside, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stage, "checkpoint.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	driver := dockerDriver{root: root, inspectionRoot: work}
	if _, _, err := driver.rewriteReadOnlyArgs([]string{"--artifact-root", stage, "--checkpoint", link}); err == nil {
		t.Fatal("accepted an artifact child symlink")
	}
}

func TestDockerContributionAdoptsContainerAfterLostCreateResponse(t *testing.T) {
	o, pos, driver, fake := dockerContributionFixture(t)
	fake.createErrAfter = true
	if err := runNextAt(o, pos, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !fake.removed {
		t.Fatal("reconciled contributor container was not removed")
	}
	if _, err := os.Lstat(driver.activeStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active container state remains after reconciled run: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(o.outDir, dockerLifecycleLogName)); err != nil {
		t.Fatalf("reconciled contribution output was not promoted: %v", err)
	}
}

func TestDockerContributionRejectsUnsafeEffectiveConfiguration(t *testing.T) {
	o, pos, _, fake := dockerContributionFixture(t)
	fake.unsafe = true
	err := runNextAt(o, pos, time.Now())
	if err == nil || !strings.Contains(err.Error(), "failed isolation verification") {
		t.Fatalf("unsafe configuration error = %v", err)
	}
	if !fake.removed {
		t.Fatal("unsafe contributor was not removed")
	}
	if _, err := os.Lstat(o.outDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe contributor output was retained: %v", err)
	}
}

func TestDockerContributionRejectsMissingEffectiveRuntimeLimits(t *testing.T) {
	for _, resource := range []string{"memory", "memory-swap", "cpu", "environment"} {
		t.Run(resource, func(t *testing.T) {
			o, pos, _, fake := dockerContributionFixture(t)
			fake.unsafeResource = resource
			err := runNextAt(o, pos, time.Now())
			if err == nil || !strings.Contains(err.Error(), "failed isolation verification") {
				t.Fatalf("unsafe runtime limit error = %v", err)
			}
			if !fake.removed {
				t.Fatal("unbounded contributor was not removed")
			}
			if _, err := os.Lstat(o.outDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unbounded contribution output exists: %v", err)
			}
		})
	}
}

func TestDockerLifecycleRuntimeEvidenceIsVersioned(t *testing.T) {
	o, pos, _, _ := dockerContributionFixture(t)
	if err := runNextAt(o, pos, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(o.outDir, dockerLifecycleLogName))
	if err != nil {
		t.Fatal(err)
	}
	var receipt dockerLifecycleReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != dockerLifecycleSchema || !receipt.Security.RuntimeLimitsVerified || !verifiedLifecycleFacts(receipt.Schema, receipt.Security) {
		t.Fatalf("new receipt lacks verified runtime evidence: %#v", receipt.Security)
	}
	legacy := receipt.Security
	legacy.RuntimeLimitsVerified = false
	legacy.CPULimitNano, legacy.MemoryLimitBytes, legacy.MemorySwapLimitBytes = 0, 0, 0
	legacy.GoMaxProcs, legacy.GoMemoryLimit, legacy.GoGCPercent = "", "", ""
	if !verifiedLifecycleFacts(dockerLifecycleSchemaV2, legacy) {
		t.Fatal("compatible v2 lifecycle evidence was rejected")
	}
	if verifiedLifecycleFacts(dockerLifecycleSchema, legacy) {
		t.Fatal("new lifecycle receipt accepted missing runtime evidence")
	}
}

func TestDockerContributionBlocksWhenRemovalCannotBeVerified(t *testing.T) {
	o, pos, _, fake := dockerContributionFixture(t)
	fake.stillPresent = true
	err := runNextAt(o, pos, time.Now())
	if err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("removal verification error = %v", err)
	}
	if _, err := os.Lstat(o.outDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate was promoted before removal: %v", err)
	}
}

func TestDockerContributionSignalCancellationRemovesExactContainer(t *testing.T) {
	o, pos, driver, fake := dockerContributionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	driver.interruptCtx = func() (context.Context, context.CancelFunc) {
		return ctx, func() {}
	}
	fake.onAttachedContext = func(attached context.Context) error {
		cancel()
		<-attached.Done()
		return attached.Err()
	}

	err := runNextAt(o, pos, time.Now())
	if err == nil || !strings.Contains(err.Error(), "forcibly removed and its absence verified") {
		t.Fatalf("signal cleanup error = %v", err)
	}
	if !fake.removed {
		t.Fatal("interrupted contributor container was not removed")
	}
	if _, err := os.Lstat(driver.activeStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted contributor lifecycle state remains: %v", err)
	}
	if _, err := os.Lstat(o.outDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted contributor output was promoted: %v", err)
	}
}

func TestDockerInterruptContextCatchesSIGTERM(t *testing.T) {
	if os.Getenv("RELAY_SIGNAL_HELPER") == "1" {
		driver := &dockerDriver{}
		ctx, stop := driver.contributionInterruptContext()
		defer stop()
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			t.Fatal("SIGTERM did not cancel the contribution context")
		}
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDockerInterruptContextCatchesSIGTERM$")
	command.Env = append(os.Environ(), "RELAY_SIGNAL_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SIGTERM helper failed: %v\n%s", err, output)
	}
}

func TestDockerPreflightRejectsRemoteEndpoint(t *testing.T) {
	_, _, driver, _ := dockerContributionFixture(t)
	t.Setenv("DOCKER_HOST", "ssh://operator@example.invalid")
	err := driver.preflight()
	if err == nil || !strings.Contains(err.Error(), "remote Docker daemons are not supported") {
		t.Fatalf("remote endpoint error = %v", err)
	}
}

func TestDockerPreflightRejectsRemoteContextEndpoint(t *testing.T) {
	_, _, driver, fake := dockerContributionFixture(t)
	t.Setenv("DOCKER_CONTEXT", "remote-production")
	t.Setenv("DOCKER_HOST", "unix:///ignored-by-context.sock")
	fake.endpoint = "tcp://docker.example.invalid:2376"
	err := driver.preflight()
	if err == nil || !strings.Contains(err.Error(), "remote Docker daemons are not supported") {
		t.Fatalf("remote context endpoint error = %v", err)
	}
}

func TestDockerPreflightRejectsChangedDaemonIdentity(t *testing.T) {
	_, _, driver, fake := dockerContributionFixture(t)
	if err := driver.preflight(); err != nil {
		t.Fatal(err)
	}
	fake.daemonID = "different-daemon-id"
	err := driver.preflight()
	if err == nil || !strings.Contains(err.Error(), "daemon identity changed") {
		t.Fatalf("changed daemon identity error = %v", err)
	}
}

func TestDockerOrphanCleanupRequiresMatchingDaemon(t *testing.T) {
	_, _, driver, fake := dockerContributionFixture(t)
	if err := driver.preflight(); err != nil {
		t.Fatal(err)
	}
	state := dockerActiveState{
		Schema: dockerActiveStateSchemaV2, ContainerID: testContainerID,
		Image: driver.image, Platform: driver.platform,
		DaemonID: "different-daemon", DaemonEndpoint: driver.daemon.Endpoint,
		HandoffDir: filepath.Join(driver.candidateRoot, ".relay-handoff-orphan"),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSONAtomic(driver.activeStatePath(), state, 0o600); err != nil {
		t.Fatal(err)
	}
	err := driver.cleanupOrphan()
	if err == nil || !strings.Contains(err.Error(), "different Docker daemon") {
		t.Fatalf("different-daemon orphan error = %v", err)
	}
	if fake.removed {
		t.Fatal("Relay removed a container through a different daemon")
	}
}

func TestBoundDockerEnvironmentDropsTargetOverrides(t *testing.T) {
	t.Setenv("DOCKER_HOST", "ssh://remote.example.invalid")
	t.Setenv("DOCKER_CONTEXT", "remote")
	t.Setenv("RELAY_DOCKER_ENV_TEST", "preserved")
	joined := "\n" + strings.Join(dockerEnvironmentWithoutTargetOverrides(), "\n") + "\n"
	if strings.Contains(joined, "\nDOCKER_HOST=") || strings.Contains(joined, "\nDOCKER_CONTEXT=") {
		t.Fatalf("Docker target overrides remain in bound environment: %s", joined)
	}
	if !strings.Contains(joined, "\nRELAY_DOCKER_ENV_TEST=preserved\n") {
		t.Fatal("unrelated environment entry was removed")
	}
}

func TestDockerHostSwapRejectsLinuxDockerDesktopVM(t *testing.T) {
	daemon := dockerDaemonFacts{
		Context: "desktop-linux", Endpoint: "unix:///run/user/1000/docker.sock",
		ID: "desktop-daemon", Name: "docker-desktop", ServerVersion: "28.0.0",
		OperatingSystem: "Docker Desktop", OSType: "linux", Architecture: "amd64",
		LocalUnixEndpoint: true,
	}
	_, err := dockerHostSwapStatus("linux", daemon)
	if err == nil || !strings.Contains(err.Error(), "whose swap Relay cannot verify") {
		t.Fatalf("Linux Docker Desktop swap error = %v", err)
	}
}

func TestDockerSecurityUsesDaemonUserNamespaceConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		options   []string
		wantMode  string
		wantRemap bool
	}{
		{name: "unremapped default", wantMode: "daemon-default-unremapped"},
		{name: "userns remap", options: []string{"name=userns"}, wantMode: "daemon-remapped", wantRemap: true},
		{name: "rootless", options: []string{"name=rootless"}, wantMode: "rootless-daemon", wantRemap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, pos, _, fake := dockerContributionFixture(t)
			fake.securityOptions = tc.options
			if err := runNextAt(o, pos, time.Now()); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(o.outDir, dockerLifecycleLogName))
			if err != nil {
				t.Fatal(err)
			}
			var receipt dockerLifecycleReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Security.UserNamespaceMode != tc.wantMode ||
				receipt.Security.UserNamespaceRemapped != tc.wantRemap {
				t.Fatalf("user namespace facts = %#v", receipt.Security)
			}
			if receipt.Daemon.UserNamespaceRemap != dockerSecurityOptionEnabled(tc.options, "name=userns") ||
				receipt.Daemon.Rootless != dockerSecurityOptionEnabled(tc.options, "name=rootless") {
				t.Fatalf("daemon security facts = %#v", receipt.Daemon)
			}
		})
	}
}

func TestDockerSecurityRejectsExplicitHostUserNamespace(t *testing.T) {
	o, pos, _, fake := dockerContributionFixture(t)
	fake.usernsMode = "host"
	err := runNextAt(o, pos, time.Now())
	if err == nil || !strings.Contains(err.Error(), "failed isolation verification") {
		t.Fatalf("host user namespace error = %v", err)
	}
}

func TestDockerContributionDoesNotReplaceConcurrentLifecycleState(t *testing.T) {
	o, pos, driver, fake := dockerContributionFixture(t)
	statePath := driver.activeStatePath()
	original := []byte("concurrent state\n")
	fake.onCreate = func() {
		if err := os.WriteFile(statePath, original, 0o600); err != nil {
			t.Errorf("create concurrent lifecycle state: %v", err)
		}
	}
	err := runNextAt(o, pos, time.Now())
	if err == nil || !strings.Contains(err.Error(), "persist contributor cleanup state") {
		t.Fatalf("concurrent lifecycle state error = %v", err)
	}
	got, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("concurrent lifecycle state was replaced: %q", got)
	}
	if !fake.removed {
		t.Fatal("new contributor was not removed after lifecycle-state conflict")
	}
}

func TestDockerContributionPersistsActualCommandBeforeCreate(t *testing.T) {
	o, pos, driver, fake := dockerContributionFixture(t)
	checked := false
	fake.onCreate = func() {
		var state dockerActiveState
		if err := setupReadJSON(driver.activeStatePath(), &state); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(state.CreateArgs, fake.createArgs) {
			t.Fatal("saved intent differs from actual Docker invocation")
		}
		if !strings.Contains(strings.Join(state.CreateArgs, " "), "/relay/output/candidate") {
			t.Fatal("missing rewritten candidate destination")
		}
		checked = true
	}
	if err := runNextAt(o, pos, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !checked {
		t.Fatal("create was not observed")
	}
}

func TestDockerContributionLaunchBoundary(t *testing.T) {
	for _, preflightFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "intent-before-boundary", true: "preflight-before-boundary"}[preflightFailure], func(t *testing.T) {
			o, pos, d, fake := dockerContributionFixture(t)
			d.executionIntentPath = filepath.Join(t.TempDir(), "intent.json")
			if preflightFailure {
				d.hostSwapStatus = func() (string, error) { return "", errors.New("preflight failed") }
			}
			crossed := false
			d.beforeCreate = func() error {
				crossed = true
				var intent dockerActiveState
				if err := setupReadJSON(d.executionIntentPath, &intent); err != nil {
					t.Fatal(err)
				}
				if len(intent.CreateArgs) == 0 {
					t.Fatal("running boundary precedes durable invocation")
				}
				return errors.New("boundary persistence failed")
			}
			if err := runNextAt(o, pos, time.Now()); err == nil {
				t.Fatal("ignored prelaunch failure")
			}
			if crossed == preflightFailure {
				t.Fatal("incorrect launch boundary ordering")
			}
			if len(fake.createArgs) != 0 {
				t.Fatal("created contributor after failed prelaunch boundary")
			}
		})
	}
}

func TestDockerContributionReportsProvenCreateNoEffect(t *testing.T) {
	o, pos, driver, fake := dockerContributionFixture(t)
	driver.executionIntentPath = filepath.Join(t.TempDir(), "intent.json")
	driver.replaceUnstartedIntent = true
	fake.createErrAfter = true
	fake.onCreate = func() { fake.removed = true }
	err := runNextAt(o, pos, time.Now())
	if !errors.Is(err, errContributorNotCreated) {
		t.Fatalf("create failure = %v", err)
	}
	for _, path := range []string{driver.activeStatePath(), driver.executionIntentPath} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("retained uncertain intent %s: %v", path, statErr)
		}
	}
	if _, statErr := os.Lstat(o.outDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("candidate unexpectedly exists: %v", statErr)
	}
}

func TestSignedCeremonyBinarySHA256SelectsConfiguredPlatform(t *testing.T) {
	amdDigest := "sha256:" + strings.Repeat("a", 64)
	armDigest := "sha256:" + strings.Repeat("b", 64)
	for _, schema := range []string{"proof-tool-mpc-ceremony-definition-v2", "proof-tool-mpc-ceremony-definition-v3", "proof-tool-mpc-ceremony-definition-v4", "proof-tool-mpc-ceremony-definition-v5"} {
		t.Run(schema, func(t *testing.T) {
			definition := `{"schema":"` + schema + `","software":{"binaries":[` +
				`{"goos":"linux","goarch":"amd64","goamd64":"v1","tool_binary":{"sha256":"` + amdDigest + `"}},` +
				`{"goos":"linux","goarch":"arm64","goarm64":"v8.0","tool_binary":{"sha256":"` + armDigest + `"}}]}}`
			path := filepath.Join(t.TempDir(), "ceremony.json")
			if err := os.WriteFile(path, []byte(definition), 0o600); err != nil {
				t.Fatal(err)
			}
			for platform, want := range map[string]string{
				"linux/amd64": amdDigest,
				"linux/arm64": armDigest,
			} {
				got, err := signedCeremonyBinarySHA256(path, platform)
				if err != nil {
					t.Fatalf("select %s: %v", platform, err)
				}
				if got != want {
					t.Fatalf("select %s = %q, want %q", platform, got, want)
				}
			}
			if _, err := signedCeremonyBinarySHA256(path, "linux/riscv64"); err == nil {
				t.Fatal("unlisted platform was accepted")
			}
			duplicate := strings.Replace(definition, `]}}`, `,{"goos":"linux","goarch":"arm64","tool_binary":{"sha256":"`+armDigest+`"}}]}}`, 1)
			if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := signedCeremonyBinarySHA256(path, "linux/arm64"); err == nil {
				t.Fatal("duplicate platform was accepted")
			}
		})
	}
}

func TestSignedCeremonyBinarySHA256TreatsV1AsSingletonPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	definition := `{"schema":"proof-tool-mpc-ceremony-definition-v1","software":{` +
		`"goos":"linux","goarch":"amd64","tool_binary":{"sha256":"` + digest + `"}}}`
	path := filepath.Join(t.TempDir(), "ceremony.json")
	if err := os.WriteFile(path, []byte(definition), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := signedCeremonyBinarySHA256(path, "linux/amd64"); err != nil || got != digest {
		t.Fatalf("select legacy binary = %q, %v", got, err)
	}
	if _, err := signedCeremonyBinarySHA256(path, "linux/arm64"); err == nil {
		t.Fatal("legacy singleton policy was accepted on another platform")
	}
}

func TestConfirmDockerNoCopiesUpdatesLocalLifecycleLog(t *testing.T) {
	dir := t.TempDir()
	hostSwapStatus := dockerLinuxSwapDisabled
	if runtime.GOOS == "darwin" {
		hostSwapStatus = dockerMacSwapUnassessed
	}
	receipt := dockerLifecycleReceipt{
		Schema: dockerLifecycleSchemaV2, ContainerID: testContainerID, RemovalVerified: true,
		HostSwapStatus: hostSwapStatus,
		Daemon: dockerDaemonFacts{
			Context: "test-local", Endpoint: "unix:///var/run/docker.sock", ID: "test-daemon-id",
			Name: "test-daemon", ServerVersion: "28.0.0", OperatingSystem: "Test Linux",
			OSType: "linux", Architecture: "arm64", LocalUnixEndpoint: true,
		},
		Security: dockerSecurityFacts{
			NetworkNone: true, ReadOnlyRoot: true, NonRoot: true, CapabilitiesOff: true,
			NoNewPrivileges: true, CoreDumpsOff: true, LogDriverOff: true,
			PrivatePID: true, PrivateIPC: true, UserNamespaceMode: "daemon-default-unremapped",
			BoundedTmpfs: true, MountsVerified: true,
		},
	}
	path := filepath.Join(dir, dockerLifecycleLogName)
	if err := writeJSONAtomic(path, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.WriteString("CLEANUP PRECAUTIONS CONFIRMED\n"); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	original := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = original; _ = read.Close() })
	if err := confirmDockerNoCopies(roleOpts{outDir: dir, docker: &dockerDriver{}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ParticipantConfirmation != "CLEANUP PRECAUTIONS CONFIRMED" || receipt.ConfirmedAt == "" {
		t.Fatalf("confirmation not recorded: %#v", receipt)
	}
}

func TestDockerContributionAdmissionPrecedesIntentAndCreation(t *testing.T) {
	o, pos, _, fake := dockerContributionFixture(t)
	c := dockerCapacityContainer{ID: strings.Repeat("b", 64)}
	c.State.Status = "running"
	c.HostConfig.NanoCPUs = 2_000_000_000
	c.HostConfig.Memory = 12 << 30
	fake.capacityContainers = []dockerCapacityContainer{c}
	if err := runNextAt(o, pos, time.Now()); err == nil || !strings.Contains(err.Error(), "insufficient unclaimed") {
		t.Fatalf("oversubscribed launch: %v", err)
	}
	if len(fake.createArgs) != 0 {
		t.Fatal("created contributor despite capacity rejection")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(o.outDir), dockerActiveStateFileName)); !os.IsNotExist(err) {
		t.Fatal("capacity rejection left contributor intent", err)
	}
}

func TestDockerContributionHoldsAdmissionThroughCreation(t *testing.T) {
	o, pos, d, fake := dockerContributionFixture(t)
	fake.onCreate = func() {
		lock, err := acquireDockerAdmission(d.daemon)
		if err == nil {
			lock.release()
			t.Error("admission lock released before create completed")
		}
	}
	fake.onAttachedContext = func(context.Context) error {
		lock, err := acquireDockerAdmission(d.daemon)
		if err != nil {
			t.Error("admission lock remained held during computation", err)
		} else {
			lock.release()
		}
		return errors.New("stop test before computation")
	}
	if err := runNextAt(o, pos, time.Now()); err == nil {
		t.Fatal("missing test interruption")
	}
	if !fake.removed {
		t.Fatal("interrupted contributor not removed")
	}
}
