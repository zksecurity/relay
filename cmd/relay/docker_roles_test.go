package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in packaging smoke test: supply locally approved immutable image IDs.
// It does not create a ceremony, publish artifacts, or use real credentials.
func TestDockerRoleImages(t *testing.T) {
	online, offline := os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), os.Getenv("RELAY_ROLE_OFFLINE_IMAGE")
	if online == "" || offline == "" {
		t.Skip("set RELAY_ROLE_ONLINE_IMAGE and RELAY_ROLE_OFFLINE_IMAGE for Docker smoke tests")
	}
	platform := os.Getenv("RELAY_ROLE_PLATFORM")
	if platform == "" {
		platform = "linux/amd64"
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("docker", append([]string{"--host", endpoint}, args...)...)
		cmd.Env = dockerEnvironmentWithoutTargetOverrides()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v: %s", args[0], err, out)
		}
		return out
	}
	for _, role := range []string{"coordinator", "witness", "mirror", "auditor", "upload-station", "release-signer", "decision-signer", "keygen"} {
		t.Run(role, func(t *testing.T) {
			o := roleTestOptions(t)
			o.role = role
			o.image = online
			o.platform = platform
			isOffline := role == "release-signer" || role == "decision-signer" || role == "keygen"
			command := []string{"relay", "help"}
			if role == "coordinator" {
				command = []string{"aws", "--version"}
			}
			if isOffline {
				o.image = offline
				command = []string{"mpc-ceremony", "help"}
			}
			if role == "keygen" {
				command = []string{"mpc-ceremony", "identity", "generate", "--identity-id", "smoke-only", "--display-name", "Smoke test", "--private-key-out", "/work/key.hex", "--public-identity-out", "/work/identity.json"}
			}
			args, err := dockerRoleArgs(o, command, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			args[0] = "create"
			id := strings.TrimSpace(string(run(t, args...)))
			t.Cleanup(func() { _ = exec.Command("docker", "--host", endpoint, "rm", "--force", id).Run() })
			var inspected []struct {
				HostConfig struct {
					NetworkMode    string
					ReadonlyRootfs bool
					CapDrop        []string
				}
				Config struct{ User string }
				Mounts []struct {
					Destination string
					RW          bool
				}
			}
			if err := json.Unmarshal(run(t, "inspect", id), &inspected); err != nil {
				t.Fatal(err)
			}
			if len(inspected) != 1 || !inspected[0].HostConfig.ReadonlyRootfs || inspected[0].Config.User == "0" {
				t.Fatal("unsafe effective container settings")
			}
			if (inspected[0].HostConfig.NetworkMode == "none") != isOffline {
				t.Fatal("wrong effective network policy")
			}
			for _, mount := range inspected[0].Mounts {
				if mount.Destination != "/work" && mount.RW {
					t.Fatalf("unexpected writable mount: %s", mount.Destination)
				}
			}
			run(t, "start", "--attach", id)
			if role == "keygen" {
				info, err := os.Stat(filepath.Join(o.work, "key.hex"))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("key mode: %v", info.Mode())
				}
				if _, err := os.Stat(filepath.Join(o.work, "identity.json")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func roleTestOptions(t *testing.T) dockerRoleOptions {
	t.Helper()
	return dockerRoleOptions{role: "coordinator", image: "sha256:" + strings.Repeat("a", 64), platform: "linux/amd64", work: privateRoleTestDir(t)}
}

func privateRoleTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	physical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return physical
}

func TestDockerRolePolicies(t *testing.T) {
	for _, role := range []string{"coordinator", "witness", "mirror", "auditor", "upload-station", "release-signer", "decision-signer", "keygen"} {
		t.Run(role, func(t *testing.T) {
			o := roleTestOptions(t)
			o.role = role
			command := []string{"mpc-ceremony", "identity", "generate"}
			args, err := dockerRoleArgs(o, command, 501, 20)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(args, " ")
			for _, required := range []string{"--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit=core=0:0", "--user 501:20", "--entrypoint=/usr/local/bin/mpc-ceremony", "--tmpfs=/tmp:", "--rm"} {
				if !strings.Contains(joined, required) {
					t.Errorf("missing %s", required)
				}
			}
			offline := role == "release-signer" || role == "decision-signer" || role == "keygen"
			if strings.Contains(joined, "--network=none") != offline {
				t.Fatal("wrong network policy")
			}
			if strings.Contains(joined, "docker.sock") {
				t.Fatal("Docker socket exposed")
			}
		})
	}
}

func TestDockerRoleRejectsUnsafeOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*dockerRoleOptions)
		command []string
	}{
		{"tag", func(o *dockerRoleOptions) { o.image = "tools:latest" }, nil},
		{"platform", func(o *dockerRoleOptions) { o.platform = "darwin/arm64" }, nil},
		{"role", func(o *dockerRoleOptions) { o.role = "unknown" }, nil},
		{"root mount", func(o *dockerRoleOptions) { o.work = "/" }, nil},
		{"missing work", func(o *dockerRoleOptions) { o.work = "" }, nil},
		{"offline credentials", func(o *dockerRoleOptions) { o.role = "release-signer"; o.credentials = "/secret" }, nil},
		{"uploader keys", func(o *dockerRoleOptions) { o.role = "upload-station"; o.keys = "/secret" }, nil},
		{"shell", func(o *dockerRoleOptions) {}, []string{"sh", "-c", "true"}},
		{"nested participant", func(o *dockerRoleOptions) {}, []string{"relay", "participant", "run"}},
		{"raw contribution", func(o *dockerRoleOptions) {}, []string{"mpc-ceremony", "phase1", "contribute"}},
		{"nested launcher", func(o *dockerRoleOptions) {}, []string{"relay", "role"}},
		{"offline upload", func(o *dockerRoleOptions) { o.role = "release-signer" }, []string{"relay", "release", "run"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := roleTestOptions(t)
			test.change(&o)
			command := test.command
			if command == nil {
				command = []string{"mpc-ceremony", "help"}
			}
			if _, err := dockerRoleArgs(o, command, 501, 20); err == nil {
				t.Fatal("unsafe options accepted")
			}
		})
	}
	o := roleTestOptions(t)
	if _, err := dockerRoleArgs(o, []string{"relay", "help"}, 0, 0); err == nil {
		t.Fatal("root accepted")
	}
}

func TestDockerRoleMountsAndArguments(t *testing.T) {
	o := roleTestOptions(t)
	o.trust = privateRoleTestDir(t)
	o.keys = privateRoleTestDir(t)
	o.credentials = filepath.Join(t.TempDir(), "aws")
	if err := os.WriteFile(o.credentials, []byte("[coordinator]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args, err := dockerRoleArgs(o, []string{"relay", "help", "a value with spaces"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, value := range []string{"dst=/keys,readonly", "dst=/trust,readonly"} {
		if !strings.Contains(joined, value) {
			t.Errorf("missing %s", value)
		}
	}
	if strings.Contains(joined, "dst=/credentials/aws") || strings.Contains(joined, "AWS_SHARED_CREDENTIALS_FILE=/credentials/aws") {
		t.Fatal("unrelated help command received cloud credentials")
	}
	if args[len(args)-1] != "a value with spaces" {
		t.Fatal("argument boundaries lost")
	}
	grantArgs, err := dockerRoleArgs(o, []string{"relay", "coordinator", "grant", "--role", "participant"}, 501, 20)
	if err != nil {
		t.Fatalf("participant grant must remain allowed: %v", err)
	}
	if !strings.Contains(strings.Join(grantArgs, " "), "dst=/credentials/aws,readonly") {
		t.Fatal("grant command lost required credentials")
	}
	o.keys = o.work
	if _, err := dockerRoleArgs(o, []string{"relay", "help"}, 501, 20); err == nil {
		t.Fatal("overlapping mounts accepted")
	}
	o.keys = privateRoleTestDir(t)
	if err := os.Symlink(o.keys, filepath.Join(o.work, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerRoleArgs(o, []string{"relay", "help"}, 501, 20); err == nil {
		t.Fatal("symlink mount accepted")
	}
}

func TestDockerRoleParticipantDoesNotFallback(t *testing.T) {
	o := dockerRoleOptions{role: "participant"}
	if err := runDockerRoleParticipant(o, []string{"run"}); err == nil {
		t.Fatal("missing profile accepted")
	}
	o.config = "/missing/profile.json"
	for _, args := range [][]string{{"run", "--config=/other"}, {"run", "-config", "/other"}, {"contribute"}, {"run"}} {
		if err := runDockerRoleParticipant(o, args); err == nil {
			t.Fatal("invalid participant launch accepted")
		}
	}
}

func TestDockerRoleRejectsRemoteEndpointBeforeExecution(t *testing.T) {
	o := roleTestOptions(t)
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	err := runDockerRole([]string{"--role", "coordinator", "--image", o.image, "--work", o.work, "--", "relay", "help"})
	if err == nil || !strings.Contains(err.Error(), "local Unix socket") {
		t.Fatalf("remote endpoint was not rejected: %v", err)
	}
}

func TestDockerRoleParticipantRejectsIgnoredSettings(t *testing.T) {
	err := runDockerRole([]string{"--role", "participant", "--config", "/unused", "--platform", "linux/arm64", "--", "status"})
	if err == nil || !strings.Contains(err.Error(), "belongs in its Docker profile") {
		t.Fatalf("participant setting was ignored: %v", err)
	}
}
