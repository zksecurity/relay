package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPinnedProofPlatforms(t *testing.T) {
	var source string
	for _, arch := range []string{"amd64", "arm64"} {
		a, commit, name, err := pinnedProofAsset(arch)
		if err != nil {
			t.Fatal(err)
		}
		if source != "" && source != commit {
			t.Fatal("architectures have different source commits")
		}
		source = commit
		if !strings.HasSuffix(a.URL, "/"+name) {
			t.Fatal("wrong asset")
		}
	}
	if _, _, _, err := pinnedProofAsset("darwin"); err == nil {
		t.Fatal("unsupported target accepted")
	}
}

func TestProofCacheRejectsModifiedAndSymlink(t *testing.T) {
	a, _, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"modified", "symlink", "nonexecutable"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "mpc-ceremony-linux-"+runtime.GOARCH+"-"+a.SHA256)
			if kind == "symlink" {
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			} else {
				mode := os.FileMode(0700)
				if kind == "nonexecutable" {
					mode = 0600
				}
				if err := os.WriteFile(path, []byte("not the approved tool"), mode); err != nil {
					t.Fatal(err)
				}
			}
			// A bad cache must fail locally, never attempt a replacement download.
			t.Setenv("PATH", "")
			if _, err := prepareProofAsset(root, runtime.GOARCH); err == nil || strings.Contains(err.Error(), "download") {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("cache evidence removed")
			}
		})
	}
}

func TestReleaseReceiptRejectsChangedBindings(t *testing.T) {
	old := releaseCommit
	releaseCommit = strings.Repeat("a", 40)
	t.Cleanup(func() { releaseCommit = old })
	a, commit, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	base := releaseToolReceipt{releaseToolReceiptSchema, releaseCommit, commit, "linux/" + runtime.GOARCH, "/usr/local/bin/relay", strings.Repeat("b", 64), "/usr/local/bin/mpc-ceremony", a.SHA256}
	raw, _ := json.Marshal(base)
	r, err := decodeReleaseToolReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.KitMode != "" || r.CompatibilityTest != "" {
		t.Fatal("invented compatibility claim")
	}
	pretty, _ := json.MarshalIndent(base, "", "  ")
	if _, err := decodeReleaseToolReceipt(pretty); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*releaseToolReceipt){
		"source":        func(r *releaseToolReceipt) { r.SourceCommit = strings.Repeat("c", 40) },
		"proof source":  func(r *releaseToolReceipt) { r.ProofCommit = strings.Repeat("c", 40) },
		"platform":      func(r *releaseToolReceipt) { r.Platform = "darwin/arm64" },
		"hash":          func(r *releaseToolReceipt) { r.ProofSHA256 = strings.Repeat("c", 64) },
		"relative path": func(r *releaseToolReceipt) { r.ProofPath = "./tool" },
		"schema":        func(r *releaseToolReceipt) { r.Schema = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			mutate(&v)
			raw, _ := json.Marshal(v)
			if _, err := decodeReleaseToolReceipt(raw); err == nil {
				t.Fatal("changed receipt accepted")
			}
		})
	}
	for _, invalid := range [][]byte{append(append([]byte{}, raw...), []byte(" {}")...), []byte(strings.Replace(string(raw), `"schema":`, `"extra":true,"schema":`, 1)), []byte(strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1))} {
		if _, err := decodeReleaseToolReceipt(invalid); err == nil {
			t.Fatal("noncanonical receipt accepted")
		}
	}
}

func TestGuidedEnvironmentRequiresPreflightAndConsent(t *testing.T) {
	p := preparationFixture(t, "participant")
	path := filepath.Join(p.d.Work, "environment.json")
	p.environmentPreflight = func() error { return errors.New("unsafe Docker endpoint") }
	if _, err := p.environment(); err == nil {
		t.Fatal("failed preflight accepted")
	}
	p.environmentPreflight = func() error { return nil }
	p.ui.input = bufio.NewReader(strings.NewReader("no\n"))
	if _, err := p.environment(); err == nil {
		t.Fatal("missing consent accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("wrote unconfirmed plan")
	}
	for i := 0; i < 2; i++ {
		p.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
		if _, err := p.environment(); err != nil {
			t.Fatal(err)
		}
	}
	var env guidedEnvironment
	if err := setupReadJSON(path, &env); err != nil {
		t.Fatal(err)
	}
	if !env.HostRemnantsNotExcluded || env.OS != "linux" {
		t.Fatal("wrong environment claims")
	}
	canonical, _ := json.Marshal(env)
	written, err := os.ReadFile(path)
	if err != nil || string(written) != string(canonical) {
		t.Fatal("environment must use proof-tool's canonical bytes, without indentation or trailing newline")
	}
	env.HostRemnantsNotExcluded = false
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
	if _, err := p.environment(); err == nil {
		t.Fatal("different environment overwritten")
	}
}

func TestGuidedEnvironmentPreservesEarlierIndentedPlan(t *testing.T) {
	p := preparationFixture(t, "participant")
	p.environmentPreflight = func() error { return nil }
	p.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
	path, err := p.environment()
	if err != nil {
		t.Fatal(err)
	}
	var env guidedEnvironment
	if err := setupReadJSON(path, &env); err != nil {
		t.Fatal(err)
	}
	indented, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(path, indented, 0600); err != nil {
		t.Fatal(err)
	}
	p.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
	fresh, err := p.environment()
	if err != nil || fresh == path {
		t.Fatal(fresh, err)
	}
	old, _ := os.ReadFile(path)
	if string(old) != string(indented) {
		t.Fatal("overwrote earlier plan")
	}
	p.ui.input = bufio.NewReader(strings.NewReader("PRECAUTIONS REVIEWED\n"))
	again, err := p.environment()
	if err != nil || again != fresh {
		t.Fatal("resume should reuse its canonical plan", again, err)
	}
}

func TestContributorEntrypointDoesNotUseHostPath(t *testing.T) {
	d := dockerDriver{ceremonyBinary: "/host-only/download/tool", image: "sha256:" + strings.Repeat("a", 64), platform: "linux/" + runtime.GOARCH}
	args := strings.Join(d.securityArgs(nil), " ")
	if strings.Contains(args, d.ceremonyBinary) || !strings.Contains(args, "/usr/local/bin/mpc-ceremony") {
		t.Fatalf("wrong container entrypoint: %s", args)
	}
}

func TestPinnedProofDownloads(t *testing.T) {
	if os.Getenv("RELAY_RELEASE_TOOLS_ONLINE") != "1" {
		t.Skip("opt-in: downloads and verifies both pinned GitHub releases")
	}
	oldCommit := releaseCommit
	releaseCommit = strings.Repeat("a", 40)
	t.Cleanup(func() { releaseCommit = oldCommit })
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root = filepath.Join(root, "tools")
			first, err := prepareProofAsset(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", "") // verified cache is usable without GitHub access
			second, err := prepareProofAsset(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			if first != second {
				t.Fatal("cache changed identity")
			}
			if arch == runtime.GOARCH {
				receipt, err := measuredReleaseTools(first.Path)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "receipt.json")
				if err := writeJSONNoReplace(path, receipt, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := verifyToolIdentities(path, first.Path); err != nil {
					t.Fatal(err)
				}
				receipt.RelaySHA256 = strings.Repeat("0", 64)
				path = filepath.Join(root, "wrong-relay.json")
				if err := writeJSONNoReplace(path, receipt, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := verifyToolIdentities(path, first.Path); err == nil {
					t.Fatal("wrong native tool hash accepted")
				}
			}
		})
	}
}

func TestReleaseImageToolReceipt(t *testing.T) {
	image, commit := os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), os.Getenv("RELAY_IMAGE_SOURCE_COMMIT")
	if image == "" || commit == "" {
		t.Skip("requires a release image and its expected source commit")
	}
	if !roleImagePattern.MatchString(image) || !launcherReleaseTag.MatchString("role-images-"+commit) {
		t.Fatal("use pinned image and full source commit")
	}
	raw, err := exec.Command("docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit=core=0:0", "--platform", "linux/"+runtime.GOARCH, "--entrypoint=/usr/local/bin/relay", image, "ceremony", "inspect-tools").Output()
	if err != nil {
		t.Fatal(err)
	}
	old := releaseCommit
	releaseCommit = commit
	t.Cleanup(func() { releaseCommit = old })
	measured, err := decodeReleaseToolReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if measured.Relay.VerifiedPath != "/usr/local/bin/relay" || measured.MPCCeremony.VerifiedPath != "/usr/local/bin/mpc-ceremony" {
		t.Fatal("unexpected installed tool paths")
	}
	// The supervisor's host-side tool location is not a Docker executable path.
	driver := dockerDriver{ceremonyBinary: "/host-only/approved-tools/mpc-ceremony", image: image, platform: "linux/" + runtime.GOARCH, client: osDockerCommandClient{binary: "docker"}}
	if stdout, stderr, err := driver.inspectionRunner(driver.ceremonyBinary, "help", "inspect", "definition"); err != nil {
		t.Fatalf("separate host path: %v: %s", err, stderr)
	} else if !strings.Contains(string(stdout), "inspect definition") {
		t.Fatal("unexpected tool output")
	}
}
