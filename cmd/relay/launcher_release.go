package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
)

var launcherReleaseTag = regexp.MustCompile(`^role-images-([0-9a-f]{40})$`)

// Set only by the attested release build after checking the checkout commit.
var releaseCommit string

func launcherCommit() string {
	if releaseCommit != "" {
		return releaseCommit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var revision string
	for _, setting := range info.Settings {
		if setting.Key == "vcs.modified" && setting.Value == "true" {
			return ""
		}
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
	}
	return revision
}

func checkLauncherRelease(commit string) error {
	if commit != "" && launcherCommit() != commit {
		return errors.New("installed launcher does not match this release; install the launcher from the same role-images release")
	}
	return nil
}

func releaseRoleTarget(role string) (string, error) {
	switch role {
	case "coordinator", "witness", "mirror", "auditor", "upload-station":
		return "online", nil
	case "keygen", "release-signer", "decision-signer":
		return "offline", nil
	case "participant":
		return "contributor", nil
	default:
		return "", errors.New("unknown release role")
	}
}

func selectReleaseImage(raw []byte, commit, role, platform string) (string, error) {
	var m struct {
		Schema   string `json:"schema"`
		Approval string `json:"approval"`
		Source   string `json:"source_commit"`
		Launcher string `json:"launcher_commit"`
		Images   []struct {
			Target   string `json:"target"`
			Platform string `json:"platform"`
			Image    string `json:"image"`
			Source   string `json:"source_commit"`
		} `json:"images"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	if m.Schema != "relay-role-image-release/v1" || m.Approval != "github-attested-ci" || m.Source != commit || m.Launcher != commit || len(m.Images) != 6 {
		return "", errors.New("release map has incompatible metadata or incomplete images")
	}
	target, err := releaseRoleTarget(role)
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	selected := ""
	for _, entry := range m.Images {
		names := map[string]string{"online": "relay-role-online", "offline": "relay-role-offline", "contributor": "relay-ceremony-tool"}
		name, ok := names[entry.Target]
		key := entry.Target + "/" + entry.Platform
		prefix := "ghcr.io/zksecurity/relay/" + name + "@sha256:"
		if !ok || (entry.Platform != "linux/amd64" && entry.Platform != "linux/arm64") || seen[key] || entry.Source != commit || !strings.HasPrefix(entry.Image, prefix) || !roleImagePattern.MatchString(entry.Image) {
			return "", errors.New("release map contains invalid, duplicate, or inconsistent image records")
		}
		seen[key] = true
		if entry.Target == target && entry.Platform == platform {
			selected = entry.Image
		}
	}
	if selected == "" {
		return "", errors.New("release has no image for this role and platform")
	}
	return selected, nil
}

func verifiedReleaseImage(tag, role, platform string) (string, string, error) {
	image, commit, _, err := verifiedReleaseImageMap(tag, role, platform)
	return image, commit, err
}

func verifiedReleaseImageMap(tag, role, platform string) (string, string, []byte, error) {
	match := launcherReleaseTag.FindStringSubmatch(tag)
	if match == nil {
		return "", "", nil, errors.New("--release requires role-images-<full-commit-sha>")
	}
	commit := match[1]
	if err := checkLauncherRelease(commit); err != nil {
		return "", "", nil, err
	}
	dir, err := os.MkdirTemp("", "relay-release-")
	if err != nil {
		return "", "", nil, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "relay-role-images.release.json")
	commands := [][]string{
		{"release", "download", tag, "--repo", "zksecurity/relay", "--pattern", "relay-role-images.release.json", "--dir", dir},
		{"attestation", "verify", file, "--repo", "zksecurity/relay", "--signer-workflow", "zksecurity/relay/.github/workflows/publish-role-images.yml", "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"},
	}
	for _, args := range commands {
		cmd := exec.Command("gh", args...)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", "", nil, fmt.Errorf("release verification failed: %w", err)
		}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", "", nil, err
	}
	image, err := selectReleaseImage(raw, commit, role, platform)
	return image, commit, raw, err
}
