package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var semanticReleaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseVersionMapping(raw []byte, version string) (string, error) {
	parts := strings.Split(string(raw), "\n")
	if !semanticReleaseTag.MatchString(version) || len(parts) != 3 || parts[0] != version || parts[2] != "" || !launcherReleaseTag.MatchString("role-images-"+parts[1]) {
		return "", errors.New("invalid or mismatched Relay version mapping")
	}
	return parts[1], nil
}

func resolveReleaseVersion(version string) (string, error) {
	dir, err := os.MkdirTemp("", "relay-version-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "relay-release-version.txt")
	run := func(args ...string) error {
		c := exec.Command("gh", args...)
		c.Stderr = os.Stderr
		return c.Run()
	}
	if err := run("release", "download", version, "--repo", "zksecurity/relay", "--pattern", filepath.Base(file), "--dir", dir); err != nil {
		return "", err
	}
	raw, err := readPreparationInput(file)
	if err != nil {
		return "", err
	}
	commit, err := parseVersionMapping(raw, version)
	if err != nil {
		return "", err
	}
	if err := run("attestation", "verify", file, "--repo", "zksecurity/relay", "--signer-workflow", "zksecurity/relay/.github/workflows/publish-role-images.yml", "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"); err != nil {
		return "", fmt.Errorf("version mapping verification failed: %w", err)
	}
	return "role-images-" + commit, nil
}

// Resolve public version selectors once at the process boundary. Saved profiles,
// manifests and cryptographic identities retain their canonical commit pins.
// Stop at -- so passthrough commands are never rewritten.
func normalizeReleaseVersions(args []string, resolve func(string) (string, error)) ([]string, error) {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		if out[i] == "--" {
			break
		}
		flag, value, equals := strings.Cut(out[i], "=")
		if flag != "--release" && flag != "--approval-release" {
			continue
		}
		if !equals {
			if i+1 == len(out) {
				continue
			}
			i++
			value = out[i]
		}
		if !semanticReleaseTag.MatchString(value) {
			continue
		}
		tag, err := resolve(value)
		if err != nil {
			return nil, err
		}
		if equals {
			out[i] = flag + "=" + tag
		} else {
			out[i] = tag
		}
	}
	return out, nil
}
