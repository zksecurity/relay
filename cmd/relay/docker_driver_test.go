package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type dockerClientFake struct {
	image        string
	platform     string
	createArgs   []string
	handoff      string
	removed      bool
	stillPresent bool
	unsafe       bool
	onCreate     func()
}

func (f *dockerClientFake) Output(args ...string) ([]byte, []byte, error) {
	switch {
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
	if len(args) != 3 || args[0] != "start" || args[1] != "--attach" || args[2] != testContainerID {
		return errors.New("unexpected attached Docker command")
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
			"PidMode": "", "IpcMode": "none", "UsernsMode": "",
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
		hostSwapStatus: func() (string, error) { return "disabled", nil },
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
	receipt := dockerLifecycleReceipt{
		Schema: dockerLifecycleSchema, ContainerID: testContainerID, RemovalVerified: true,
		Security: dockerSecurityFacts{
			NetworkNone: true, ReadOnlyRoot: true, NonRoot: true, CapabilitiesOff: true,
			NoNewPrivileges: true, CoreDumpsOff: true, LogDriverOff: true,
			PrivatePID: true, PrivateIPC: true, NoHostUserNS: true, BoundedTmpfs: true, MountsVerified: true,
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
