package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/upgrade"
)

type upgradeAssets struct{ root, bundle, trustedRoot string }

func newUpgradeAssets(bundle, trustedRoot string) (*upgradeAssets, func(), error) {
	if (bundle == "") != (trustedRoot == "") {
		return nil, nil, errors.New("offline verification requires both --bundle and independently trusted --trusted-root")
	}
	if bundle != "" {
		for _, path := range []string{bundle, trustedRoot} {
			if err := validateCommitLocalPath(path); err != nil {
				return nil, nil, err
			}
		}
		resolvedBundle, err := filepath.EvalSymlinks(bundle)
		if err != nil {
			return nil, nil, err
		}
		resolvedRoot, err := filepath.EvalSymlinks(trustedRoot)
		if err != nil {
			return nil, nil, err
		}
		bundle, trustedRoot = resolvedBundle, resolvedRoot
		if _, err := pathWithin(bundle, trustedRoot, "/bundle"); err == nil {
			return nil, nil, errors.New("trust roots must not come from the transferred bundle")
		}
		if _, err := readTesseraRegularFile(trustedRoot, 4<<20, false); err != nil {
			return nil, nil, err
		}
	}
	root, err := os.MkdirTemp("", "relay-application-assets-")
	if err != nil {
		return nil, nil, err
	}
	return &upgradeAssets{root: root, bundle: bundle, trustedRoot: trustedRoot}, func() { os.RemoveAll(root) }, nil
}

func upgradeAssetLimit(asset string) int64 {
	if strings.HasPrefix(asset, "relay-darwin-") || strings.HasPrefix(asset, "relay-linux-") {
		return 128 << 20
	}
	return 1 << 20
}

func (a *upgradeAssets) get(commit, asset string) ([]byte, error) {
	if !launcherReleaseTag.MatchString("role-images-"+commit) || filepath.Base(asset) != asset || asset == "." || asset == ".." {
		return nil, errors.New("invalid release asset path")
	}
	dir := filepath.Join(a.root, commit)
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, err
	}
	if a.bundle == "" {
		return upgradeDownload(dir, commit, asset)
	}
	// Snapshot transferred bytes before verification. All later reads use that
	// snapshot, so replacing removable media cannot replace verified bytes.
	raw, err := readTesseraRegularFile(filepath.Join(a.bundle, commit, asset), upgradeAssetLimit(asset), false)
	if err != nil {
		return nil, err
	}
	proof, err := readTesseraRegularFile(filepath.Join(a.bundle, commit, asset+".sigstore.jsonl"), 4<<20, false)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, asset)
	if err := publishPublicInput(file, raw); err != nil {
		return nil, err
	}
	if err := publishPublicInput(file+".sigstore.jsonl", proof); err != nil {
		return nil, err
	}
	args := []string{"attestation", "verify", file, "--bundle", file + ".sigstore.jsonl", "--custom-trusted-root", a.trustedRoot, "--repo", "zksecurity/relay", "--signer-workflow", "zksecurity/relay/.github/workflows/publish-role-images.yml", "--source-ref", "refs/heads/main", "--source-digest", commit, "--deny-self-hosted-runners"}
	c := exec.Command("gh", args...)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("offline provenance verification failed for %s: %w", asset, err)
	}
	return raw, nil
}

// The preparation station downloads only public release assets. It does not
// read ceremony folders, keys, grants or cloud credentials.
func runUpgradeBundle(args []string) error {
	f := flag.NewFlagSet("ceremony upgrade-bundle", flag.ContinueOnError)
	original := f.String("original-release", "", "original role-images release")
	source := f.String("source-release", "", "currently selected application release")
	target := f.String("release", "", "target role-images release")
	role := f.String("role", "", "ceremony role")
	host := f.String("host", "", "destination host OS/architecture")
	platform := f.String("platform", "", "destination Docker platform")
	out := f.String("out", "", "fresh public output folder")
	if err := f.Parse(args); err != nil {
		return err
	}
	for _, tag := range []string{*original, *source, *target} {
		if !launcherReleaseTag.MatchString(tag) {
			return errors.New("original, source and target exact releases are required")
		}
	}
	if f.NArg() != 0 || !filepath.IsAbs(*out) || filepath.Clean(*out) != *out {
		return errors.New("supply a fresh absolute output folder")
	}
	d := upgrade.DeclarationV2{OriginalRelease: strings.TrimPrefix(*original, "role-images-"), SourceApp: strings.TrimPrefix(*source, "role-images-"), TargetApp: strings.TrimPrefix(*target, "role-images-"), Role: *role, Host: *host, Platform: *platform}
	// Reject path input before downloading any asset.
	if !guidedName.MatchString(*role) || (*host != "darwin/arm64" && *host != "darwin/amd64" && *host != "linux/arm64" && *host != "linux/amd64") || (*platform != "linux/arm64" && *platform != "linux/amd64") {
		return errors.New("unsupported role/host/platform")
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	a, cleanup, err := newUpgradeAssets("", "")
	if err != nil {
		return err
	}
	defer cleanup()
	copyAsset := func(commit, asset string) ([]byte, error) {
		raw, err := a.get(commit, asset)
		if err != nil {
			return nil, err
		}
		file := filepath.Join(a.root, commit, asset)
		attestDir, err := os.MkdirTemp(a.root, "attestation-")
		if err != nil {
			return nil, err
		}
		c := exec.Command("gh", "attestation", "download", file, "--repo", "zksecurity/relay")
		c.Dir = attestDir
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return nil, err
		}
		proof, err := readTesseraRegularFile(filepath.Join(attestDir, "sha256:"+upgradeBytesHash(raw)+".jsonl"), 4<<20, false)
		if err != nil {
			return nil, err
		}
		dest := filepath.Join(*out, commit)
		if err := ensurePrivateDirectory(dest); err != nil {
			return nil, err
		}
		if err := publishPublicInput(filepath.Join(dest, asset), raw); err != nil {
			return nil, err
		}
		if err := publishPublicInput(filepath.Join(dest, asset+".sigstore.jsonl"), proof); err != nil {
			return nil, err
		}
		return raw, nil
	}
	raw, err := copyAsset(d.TargetApp, d.AssetName())
	if err != nil {
		return err
	}
	actual, err := upgrade.DecodeV2(raw)
	if err != nil {
		return err
	}
	if actual.OriginalRelease != d.OriginalRelease || actual.SourceApp != d.SourceApp || actual.TargetApp != d.TargetApp || actual.Role != d.Role || actual.Host != d.Host || actual.Platform != d.Platform {
		return errors.New("declaration does not match requested bundle")
	}
	report, err := copyAsset(d.TargetApp, "upgrade-qualification-"+strings.TrimPrefix(actual.QualificationSHA256, "sha256:")+".json")
	if err != nil {
		return err
	}
	q, err := upgrade.VerifyQualification(report, actual)
	if err != nil {
		return err
	}
	if "sha256:"+upgradeBytesHash(report) != actual.QualificationSHA256 {
		return errors.New("qualification hash mismatch")
	}
	if _, err := copyAsset(d.OriginalRelease, "relay-role-images.release.json"); err != nil {
		return err
	}
	if _, err := copyAsset(d.OriginalRelease, "ceremony-software-manifest-v3.json"); err != nil {
		return err
	}
	if _, err := copyAsset(d.TargetApp, "relay-role-images.release.json"); err != nil {
		return err
	}
	binary, err := copyAsset(d.TargetApp, "relay-"+strings.ReplaceAll(d.Host, "/", "-"))
	if err != nil {
		return err
	}
	if "sha256:"+upgradeBytesHash(binary) != q.LauncherSHA256 {
		return errors.New("bundle binary was not qualified")
	}
	if err := publishPublicInput(filepath.Join(*out, "COMPLETE"), []byte(actual.AssetName()+"\n")); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Public update bundle prepared. The offline machine must independently verify its provenance using previously trusted roots. Original Docker images must already be cached; no signing key was copied.")
	return nil
}
