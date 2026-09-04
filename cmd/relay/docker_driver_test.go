package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type dockerClientFake struct {
	image             string
	platform          string
	createArgs        []string
	handoff           string
	removed           bool
	stillPresent      bool
	unsafe            bool
	onCreate          func()
	host              string
	endpoint          string
	daemonID          string
	usernsMode        string
	securityOptions   []string
	onAttachedContext func(context.Context) error
}

func (f *dockerClientFake) Output(args ...string) ([]byte, []byte, error) {
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
			"SecurityOptions": f.securityOptions,
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
		return []byte(testContainerID + "\n"), nil, nil
	case len(args) == 2 && args[0] == "inspect":
		if f.removed && !f.stillPresent {
			return nil, []byte("No such container"), errors.New("exit status 1")
		}
		return f.inspectionJSON(), nil, nil
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
	if len(args) > 0 && args[0] == "run" {
		for index, arg := range args {
			if arg != "--mount" || index+1 >= len(args) {
				continue
			}
			var source, destination string
			for _, part := range strings.Split(args[index+1], ",") {
				if strings.HasPrefix(part, "src=") {
					source = strings.TrimPrefix(part, "src=")
				}
				if strings.HasPrefix(part, "dst=") {
					destination = strings.TrimPrefix(part, "dst=")
				}
			}
			if destination == "/relay/output" {
				evidence := filepath.Join(source, "evidence")
				if err := os.Mkdir(evidence, 0o700); err != nil {
					return err
				}
				for _, name := range []string{"host-wipe.json", "host-wipe.sig"} {
					if err := os.WriteFile(filepath.Join(evidence, name), []byte("public "+name), 0o600); err != nil {
						return err
					}
				}
				return nil
			}
		}
		return errors.New("host-wipe Docker run has no output mount")
	}
	if len(args) != 3 || args[0] != "start" || args[1] != "--attach" || args[2] != testContainerID {
		return errors.New("unexpected attached Docker command")
	}
	if f.onAttachedContext != nil {
		return f.onAttachedContext(ctx)
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
	for index, arg := range f.createArgs {
		if arg == "--user" && index+1 < len(f.createArgs) {
			user = f.createArgs[index+1]
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
	record := []map[string]any{{
		"Config": map[string]any{"Image": image, "User": user},
		"HostConfig": map[string]any{
			"NetworkMode": network, "ReadonlyRootfs": true, "Privileged": false,
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
	if err := runNextAt(o, pos, time.Now()); err != nil {
		t.Fatal(err)
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
		Schema: dockerActiveStateSchema, ContainerID: testContainerID,
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

func TestSignedCeremonyBinarySHA256SelectsConfiguredPlatform(t *testing.T) {
	amdDigest := "sha256:" + strings.Repeat("a", 64)
	armDigest := "sha256:" + strings.Repeat("b", 64)
	definition := `{"schema":"proof-tool-mpc-ceremony-definition-v2","software":{"binaries":[` +
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
		Schema: dockerLifecycleSchema, ContainerID: testContainerID, RemovalVerified: true,
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
	if _, err := write.WriteString("NO COPIES RETAINED\n"); err != nil {
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
	if receipt.ParticipantConfirmation != "NO COPIES RETAINED" || receipt.ConfirmedAt == "" {
		t.Fatalf("confirmation not recorded: %#v", receipt)
	}
}

func TestDockerHostWipeAttestationUsesFreshNarrowHandoff(t *testing.T) {
	o, _, driver, _ := dockerContributionFixture(t)
	outDir := filepath.Join(filepath.Dir(o.outDir), "host-wipe-evidence")
	if err := driver.attestHostWipe(o, time.Now(), outDir); err != nil {
		t.Fatal(err)
	}
	if err := validateHostWipeHandoff(outDir); err != nil {
		t.Fatal(err)
	}
	if err := driver.attestHostWipe(o, time.Now(), outDir); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing host-wipe output error = %v", err)
	}
}

func TestConfirmMacHostWipeRequiresExactStatement(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.WriteString("MAC WIPED AND CLEANLY REINSTALLED\n"); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	original := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = original; _ = read.Close() })
	if err := confirmMacHostWipe(); err != nil {
		t.Fatal(err)
	}
}
