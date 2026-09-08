package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	releaseassets "github.com/zksecurity/relay/release"
)

type proofReleaseAsset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

var proofReleaseURL = regexp.MustCompile(`^https://github.com/zksecurity/proof-tool/releases/download/mpc-ci-([0-9a-f]{40})/(mpc-ceremony|mpc-ceremony-linux-arm64)$`)

func pinnedProofAsset(arch string) (proofReleaseAsset, string, string, error) {
	var inputs struct {
		Schema string                       `json:"schema"`
		MPC    map[string]proofReleaseAsset `json:"mpc"`
	}
	if err := json.Unmarshal(releaseassets.RoleImageInputs(), &inputs); err != nil {
		return proofReleaseAsset{}, "", "", err
	}
	a, ok := inputs.MPC["linux_"+arch]
	match := proofReleaseURL.FindStringSubmatch(a.URL)
	name := "mpc-ceremony"
	if arch == "arm64" {
		name += "-linux-arm64"
	}
	if inputs.Schema != "relay-role-image-inputs/v1" || !ok || (arch != "amd64" && arch != "arm64") || len(match) != 3 || match[2] != name || !sha256HexPattern.MatchString(a.SHA256) {
		return a, "", "", errors.New("launcher has invalid pinned proof-tool release inputs")
	}
	return a, match[1], name, nil
}

// Downloads happen during explicit online preparation, never during a turn.
func prepareProofAsset(root, arch string) (setupBinary, error) {
	a, commit, name, err := pinnedProofAsset(arch)
	if err != nil {
		return setupBinary{}, err
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return setupBinary{}, err
	}
	path := filepath.Join(root, "mpc-ceremony-linux-"+arch+"-"+a.SHA256)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return setupBinary{}, errors.New("cached proof tool must be an executable regular file")
		}
		hash, err := setupFileHash(path)
		if err != nil {
			return setupBinary{}, err
		}
		if hash != a.SHA256 {
			return setupBinary{}, errors.New("cached proof tool changed; preserve it and investigate")
		}
		return setupBinary{path, hash}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return setupBinary{}, err
	}
	tmp, err := os.MkdirTemp(root, ".download-")
	if err != nil {
		return setupBinary{}, err
	}
	defer os.RemoveAll(tmp)
	file := filepath.Join(tmp, name)
	for _, args := range [][]string{
		{"release", "download", "mpc-ci-" + commit, "--repo", "zksecurity/proof-tool", "--pattern", name, "--dir", tmp},
		{"attestation", "verify", file, "--repo", "zksecurity/proof-tool", "--signer-workflow", "zksecurity/proof-tool/.github/workflows/publish-mpc-ceremony-release.yml", "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"},
	} {
		cmd := exec.Command("gh", args...)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return setupBinary{}, fmt.Errorf("authenticate proof-tool download: %w", err)
		}
	}
	hash, err := setupFileHash(file)
	if err != nil {
		return setupBinary{}, err
	}
	if hash != a.SHA256 {
		return setupBinary{}, errors.New("downloaded proof tool differs from the launcher release pin")
	}
	if err := os.Chmod(file, 0555); err != nil {
		return setupBinary{}, err
	}
	if err := os.Link(file, path); err != nil {
		return setupBinary{}, err
	}
	return setupBinary{path, hash}, nil
}

func (w *coordinatorWizard) prepareApprovedArchitectures() error {
	if w.d.ArchitecturePolicy == "single" || w.d.ArchitecturePolicy == "custom" || (w.d.ArchitecturePolicy == "" && len(w.d.Binaries) > 0) {
		return nil
	}
	if err := checkLauncherRelease(strings.TrimPrefix(w.d.Release, "role-images-")); err != nil {
		return err
	}
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	} else if runtime.GOARCH != "amd64" {
		return errors.New("unsupported coordinator architecture")
	}
	fmt.Fprintln(w.output, "Preparing the authenticated companion build so Intel/AMD and ARM64 computers can participate. This does not execute the downloaded binary on the host.")
	b, err := prepareProofAsset(filepath.Join(w.d.Work, "approved-tools"), other)
	if err != nil {
		return err
	}
	w.d.ArchitecturePolicy = "both"
	w.d.Binaries = []setupBinary{b}
	return w.save()
}
