package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in: disposable commands only; no ceremony keys or artifacts.
// The daemon policy is temporarily changed and restored under admission locking.
func TestDockerAdmissionLiveLifecycle(t *testing.T) {
	image := os.Getenv("RELAY_RESOURCE_LIVE_IMAGE")
	if image == "" || os.Getenv("RELAY_RESOURCE_LIVE_ACK") != "DISPOSABLE 2CPU 6GIB" {
		t.Skip("requires explicit disposable Docker qualification configuration")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("run live resource qualification on Linux")
	}
	binary, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	d := dockerDriver{image: image, platform: "linux/" + runtime.GOARCH, client: osDockerCommandClient{binary: binary}}
	if err := d.authenticateDaemon(); err != nil {
		t.Fatal(err)
	}
	measure, stderr, err := d.client.Output("create", "--network=none", "--read-only", "--cpus=1", "--memory=256m", "--memory-swap=256m", "--entrypoint=/usr/local/bin/mpc-ceremony", image, "--help")
	if err != nil {
		t.Fatalf("create measurement: %v %s", err, stderr)
	}
	measureID := strings.TrimSpace(string(measure))
	if !validContainerID(measureID) {
		t.Fatal("invalid measurement ID")
	}
	t.Cleanup(func() { d.client.Output("rm", "--force", measureID) })
	proof := filepath.Join(t.TempDir(), "proof")
	if raw, err := exec.Command(binary, "--host", d.daemon.Endpoint, "cp", measureID+":/usr/local/bin/mpc-ceremony", proof).CombinedOutput(); err != nil {
		t.Fatalf("copy measured proof: %v %s", err, raw)
	}
	raw, err := os.ReadFile(proof)
	if err != nil {
		t.Fatal(err)
	}
	asset, _, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != asset.SHA256 {
		t.Fatal("image proof does not match release pin")
	}
	if _, stderr, err := d.client.Output("rm", measureID); err != nil {
		t.Fatalf("remove measurement: %v %s", err, stderr)
	}
	lock, err := acquireDockerAdmission(d.daemon)
	if err != nil {
		t.Fatal(err)
	}
	path := dockerResourcePolicyPath(d.daemon.ID)
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		lock.release()
		t.Fatal(readErr)
	}
	containers, err := inspectDockerCapacityContainers(d.client)
	if err != nil {
		lock.release()
		t.Fatal(err)
	}
	policy := dockerResourcePolicy{Schema: dockerResourcePolicySchema, Mode: "operator-budget", DaemonID: d.daemon.ID, CPUs: d.daemon.CPUs, MemoryBytes: d.daemon.MemoryBytes, Budget: dockerRemainingCapacity{CPUNano: 2_000_000_000, MemoryBytes: 6 << 30}, Unknown: map[string]string{}, AcknowledgedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, c := range containers {
		if c.State.Status == "exited" || c.State.Status == "dead" {
			continue
		}
		if c.HostConfig.NanoCPUs == 0 || c.HostConfig.Memory == 0 {
			policy.Unknown[c.ID] = dockerUnknownWorkloadDigest(c)
		}
	}
	if _, err := remainingDockerPolicyCapacity(d.daemon, containers, dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}, &policy); err != nil {
		lock.release()
		t.Fatal(err)
	}
	if err := writeJSONAtomic(path, policy, 0600); err != nil {
		lock.release()
		t.Fatal(err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		lock.release()
		t.Fatal(err)
	}
	lock.release()
	t.Cleanup(func() {
		lock, err := acquireDockerAdmission(d.daemon)
		if err != nil {
			t.Error(err)
			return
		}
		defer lock.release()
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, installed) {
			t.Error("policy changed during qualification; refusing to overwrite it")
			return
		}
		if errors.Is(readErr, os.ErrNotExist) {
			err = os.Remove(path)
		} else {
			err = os.WriteFile(path, previous, 0600)
		}
		if err != nil {
			t.Error(err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			t.Error(err)
		}
	})
	o := dockerRoleOptions{role: "decision-signer", image: image, platform: d.platform, work: t.TempDir()}
	if err := os.Chmod(o.work, 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		command []string
		success bool
	}{
		{"success", []string{"mpc-ceremony", "--help"}, true},
		{"failure", []string{"mpc-ceremony", "no-such-command"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := dockerRoleArgs(o, test.command, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			id, err := prepareAdmittedDockerRole(d.client, d.daemon, o, test.command, args)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.client.Output("rm", "--force", id) })
			inspection, _, err := d.client.Output("inspect", id)
			if err != nil {
				t.Fatal(err)
			}
			var records []struct {
				HostConfig struct {
					NanoCPUs, Memory, MemorySwap int64
					NetworkMode                  string
				}
			}
			if json.Unmarshal(inspection, &records) != nil || len(records) != 1 || records[0].HostConfig.NanoCPUs != 2_000_000_000 || records[0].HostConfig.Memory != 6<<30 || records[0].HostConfig.MemorySwap != 6<<30 || records[0].HostConfig.NetworkMode != "none" {
				t.Fatal("actual resource/isolation settings differ")
			}
			if second, err := prepareAdmittedDockerRole(d.client, d.daemon, o, test.command, args); err == nil {
				d.client.Output("rm", "--force", second)
				t.Fatal("duplicate admitted")
			}
			stdout, stderr, err := d.client.Output("start", "--attach", id)
			if (err == nil) != test.success {
				t.Fatalf("wrong attached exit result: %v %s %s", err, stdout, stderr)
			}
			if test.success && len(stdout) == 0 {
				t.Fatal("attached stdout lost")
			}
			ids, stderr, err := d.client.Output("container", "ls", "--all", "--no-trunc", "--filter", "id="+id, "--format", "{{.ID}}")
			if err != nil || strings.TrimSpace(string(ids)) != "" {
				t.Fatalf("auto removal not confirmed: %v %s %s", err, ids, stderr)
			}
		})
	}
}
