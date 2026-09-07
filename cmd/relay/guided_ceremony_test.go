package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type guidedDockerFake struct {
	dockerClientFake
	present   bool
	pulled    bool
	requested []string
}

func (f *guidedDockerFake) BindHost(host string) dockerCommandClient { f.host = host; return f }
func (f *guidedDockerFake) Output(args ...string) ([]byte, []byte, error) {
	if len(args) > 1 && args[0] == "image" {
		if !f.present {
			return nil, nil, errors.New("missing image")
		}
		return []byte(f.platform), nil, nil
	}
	return f.dockerClientFake.Output(args...)
}
func (f *guidedDockerFake) Attached(_ io.Writer, _ io.Writer, args ...string) error {
	if len(args) != 4 || args[0] != "pull" || args[1] != "--platform" {
		return errors.New("unexpected image operation")
	}
	f.requested = append([]string(nil), args...)
	f.pulled = true
	f.present = true
	return nil
}

func TestGuidedImagePreparation(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	digest := "registry.example/tools@sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name                               string
		present, pull, wantPull, wantError bool
		image, platform                    string
	}{
		{"cached", true, true, false, false, digest, "linux/arm64"},
		{"download", false, true, true, false, digest, "linux/arm64"},
		{"open never downloads", false, false, false, true, digest, "linux/arm64"},
		{"local ID cannot download", false, true, false, true, "sha256:" + strings.Repeat("a", 64), "linux/arm64"},
		{"mutable tag", true, true, false, true, "tools:latest", "linux/arm64"},
		{"wrong architecture", true, false, false, true, digest, "linux/amd64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &guidedDockerFake{dockerClientFake: dockerClientFake{platform: "linux/arm64"}, present: test.present}
			err := prepareGuidedImageWithClient(fake, test.image, test.platform, test.pull)
			if (err != nil) != test.wantError || fake.pulled != test.wantPull {
				t.Fatalf("error=%v pull=%v", err, fake.pulled)
			}
			if !test.wantError && fake.host != "unix:///var/run/docker.sock" {
				t.Fatal("endpoint not pinned")
			}
			if fake.pulled && fake.requested[3] != digest {
				t.Fatal("download did not use exact digest")
			}
		})
	}
}

func TestGuidedConfirmationPreservesLaterInput(t *testing.T) {
	input := strings.NewReader("y\nNO COPIES RETAINED\n")
	if err := confirmGuided(input, io.Discard); err != nil {
		t.Fatal(err)
	}
	remaining, _ := io.ReadAll(input)
	if string(remaining) != "NO COPIES RETAINED\n" {
		t.Fatalf("consumed later confirmation: %q", remaining)
	}
	for _, value := range []string{"", "y", "n\n", "yes\n", "y               \n"} {
		if err := confirmGuided(strings.NewReader(value), io.Discard); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestGuidedProfilesAndNames(t *testing.T) {
	root := privateRoleTestDir(t)
	for _, name := range []string{"../escape", "/tmp", "x/y", "", "Hello"} {
		if _, err := guidedDirectory(root, name, "witness"); err == nil {
			t.Fatal("unsafe name accepted")
		}
	}
	p := guidedProfile{Schema: guidedSchema, Name: "demo", Role: "witness", Command: []string{"relay", "help"}}
	path := filepath.Join(root, "profile.json")
	if err := writeJSONNoReplace(path, p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuidedProfile(path, "demo", "witness"); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuidedProfile(path, "other", "witness"); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	if err := writeJSONNoReplace(path, p, 0o600); err == nil {
		t.Fatal("profile overwritten")
	}
	link := filepath.Join(root, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuidedProfile(link, "demo", "witness"); err == nil {
		t.Fatal("symlink profile accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuidedProfile(path, "demo", "witness"); err == nil {
		t.Fatal("public profile accepted")
	}
}

func TestGuidedAttemptRecovery(t *testing.T) {
	dir := privateRoleTestDir(t)
	if err := checkGuidedAttempts(dir); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "attempt-100.json")
	if err := writeJSONNoReplace(first, guidedAttempt{StartedAt: "first"}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkGuidedAttempts(dir); err == nil {
		t.Fatal("unfinished task ignored")
	}
	if err := writeJSONNoReplace(first+".done", guidedAttempt{StartedAt: "first", CompletedAt: "later", Success: false}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkGuidedAttempts(dir); err == nil {
		t.Fatal("failed task ignored")
	}
	second := filepath.Join(dir, "attempt-200.json")
	if err := writeJSONNoReplace(second, guidedAttempt{StartedAt: "reviewed retry"}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(second+".done", guidedAttempt{StartedAt: "reviewed retry", CompletedAt: "done", Success: true}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkGuidedAttempts(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatal("old recovery record was removed")
	}
}

func TestGuidedBlocksUnknownCandidateState(t *testing.T) {
	dir := privateRoleTestDir(t)
	check := func() error { return guardFreshGuidedContribution(dir, "phase1", "ceremony", "person") }
	if err := check(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".relay-participant-run-abc.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("partial candidate did not block a new contribution")
	}
}

func TestGuidedRetainsOtherPhaseCandidates(t *testing.T) {
	parent := privateRoleTestDir(t)
	candidate, _, manifest := candidateFixture(t)
	if err := os.Rename(candidate, filepath.Join(parent, "retained-phase1")); err != nil {
		t.Fatal(err)
	}
	if err := guardFreshGuidedContribution(parent, "phase1", manifest.CeremonyID, manifest.ParticipantID); err == nil {
		t.Fatal("current-phase candidate ignored")
	}
	if err := guardFreshGuidedContribution(parent, "phase2", manifest.CeremonyID, manifest.ParticipantID); err != nil {
		t.Fatal(err)
	}
	if err := guardFreshGuidedContribution(parent, "phase2", manifest.CeremonyID, "someone-else"); err == nil {
		t.Fatal("unrelated candidate silently ignored")
	}
}

func TestGuidedRejectsInlineSecretCommands(t *testing.T) {
	for _, args := range [][]string{{"aws", "configure", "set", "aws_secret_access_key", "example"}, {"tool", "--password=example"}, {"tool", "--private-key-hex", "example"}} {
		if err := checkSavedCommand(args); err == nil {
			t.Fatal("inline secret command accepted")
		}
	}
	if err := checkSavedCommand([]string{"mpc-ceremony", "identity", "generate", "--private-key-out", "/work/key.hex"}); err != nil {
		t.Fatal(err)
	}
}

// Tests the real saved-settings -> confirmation -> child launcher boundary.
// Uses harmless AWS version output, no real credentials or ceremony keys.
func TestGuidedDockerOpen(t *testing.T) {
	image := os.Getenv("RELAY_ROLE_ONLINE_IMAGE")
	if image == "" {
		t.Skip("set RELAY_ROLE_ONLINE_IMAGE for the real guided Docker smoke test")
	}
	root := privateRoleTestDir(t)
	binary := filepath.Join(root, "relay")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	settings := filepath.Join(root, "settings")
	setup := []string{"ceremony", "setup", "guided-demo", "--settings-root", settings, "--role", "coordinator", "--image", image, "--download=false", "--", "aws", "--version"}
	if out, err := exec.Command(binary, setup...).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	profilePath := filepath.Join(settings, "guided-demo", "coordinator", "profile.json")
	profile, err := readGuidedProfile(profilePath, "guided-demo", "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Platform != "linux/"+runtimeArchForGuidedTest() {
		t.Fatal("wrong detected architecture")
	}
	args := []string{"ceremony", "open", "guided-demo", "--settings-root", settings, "--role", "coordinator"}
	decline := exec.Command(binary, args...)
	decline.Stdin = strings.NewReader("n\n")
	if out, err := decline.CombinedOutput(); err == nil || bytes.Contains(out, []byte("aws-cli/")) {
		t.Fatalf("declined task executed: %v %s", err, out)
	}
	accept := exec.Command(binary, args...)
	accept.Stdin = strings.NewReader("y\n")
	out, err := accept.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("aws-cli/")) {
		t.Fatalf("open: %v %s", err, out)
	}
	if err := checkGuidedAttempts(filepath.Join(settings, "guided-demo", "coordinator", "activity")); err != nil {
		t.Fatal(err)
	}
	// A second setup may not silently replace saved intent.
	if out, err := exec.Command(binary, setup...).CombinedOutput(); err == nil {
		t.Fatalf("setup overwrote profile: %s", out)
	}
	var decoded map[string]any
	raw, _ := os.ReadFile(profilePath)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, exists := decoded["private_key"]; exists {
		t.Fatal("private key contents saved")
	}
}

func runtimeArchForGuidedTest() string {
	platform, _ := machineDockerPlatform()
	return strings.TrimPrefix(platform, "linux/")
}
