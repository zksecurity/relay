package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/upgrade"
)

// Reviewed policy names candidates to qualify, never asserts that tests passed.
// Reports must come from qualification of the exact built artifacts. Empty
// policy produces no authority and requires no fabricated test reports.
type upgradePolicyV2 struct {
	Schema string                  `json:"schema"`
	Pairs  []upgrade.DeclarationV2 `json:"pairs"`
}

// Equal immutable digests explicitly request a native-only update. Authenticate
// that runtime through the original map, not a fabricated target release map.
func upgradeV2DeclaredOnlineImage(original, target []byte, d upgrade.DeclarationV2) (string, error) {
	if d.OnlineImage != "" && d.OnlineImage == d.OriginalImage {
		return selectReleaseImage(original, d.OriginalRelease, "coordinator", d.Platform)
	}
	return selectReleaseImage(target, d.TargetApp, "coordinator", d.Platform)
}

func generateUpgradeV2(d upgrade.DeclarationV2, target string, originalMap, targetMap, report, launcher []byte) (map[string][]byte, error) {
	if d.TargetApp != "" && d.TargetApp != target {
		return nil, errors.New("policy targets another commit")
	}
	d.TargetApp = target
	image, err := selectReleaseImage(originalMap, d.OriginalRelease, d.Role, d.Platform)
	if err != nil {
		return nil, err
	}
	signer, err := selectReleaseImage(originalMap, d.OriginalRelease, "decision-signer", d.Platform)
	if err != nil {
		return nil, err
	}
	if d.OriginalImage != image || d.SigningImage != signer {
		return nil, errors.New("policy differs from original runtime map")
	}
	if d.Role != "participant" && d.Role != "release-signer" && d.OnlineImage != d.OriginalImage {
		d.OnlineImage, err = selectReleaseImage(targetMap, target, "coordinator", d.Platform)
		if err != nil {
			return nil, err
		}
	}
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(report)
	if err := d.Validate(); err != nil {
		return nil, err
	}
	q, err := upgrade.VerifyQualification(report, d)
	if err != nil {
		return nil, err
	}
	if q.LauncherSHA256 != "sha256:"+upgradeBytesHash(launcher) {
		return nil, errors.New("qualification used different launcher bytes")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{d.AssetName(): raw, "upgrade-qualification-" + upgradeBytesHash(report) + ".json": report}, nil
}

func runUpgradeManifestsV2(args []string) error {
	f := flag.NewFlagSet("ceremony upgrade-manifests-v2", flag.ContinueOnError)
	policyPath := f.String("policy", "", "reviewed v2 policy")
	reports := f.String("reports", "", "qualification report folder from this build")
	originals := f.String("originals", "", "authenticated original release maps by commit")
	images := f.String("role-images", "", "target release image map")
	launchers := f.String("launchers", "", "exact qualified native binaries")
	out := f.String("out", "", "fresh declaration directory")
	published := f.Bool("reviewed-published", false, "approve previously published exact binaries using reviewed local reports")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *out == "" {
		return errors.New("fresh output directory required")
	}
	var p upgradePolicyV2
	if err := setupReadJSON(*policyPath, &p); err != nil {
		return err
	}
	if p.Schema != "relay-upgrade-policy/v2" || p.Pairs == nil || len(p.Pairs) > 128 {
		return errors.New("invalid v2 upgrade policy")
	}
	files := map[string][]byte{}
	var assets *upgradeAssets
	if *published && len(p.Pairs) > 0 {
		var cleanup func()
		var err error
		assets, cleanup, err = newUpgradeAssets("", "")
		if err != nil {
			return err
		}
		defer cleanup()
	}
	var publishedTarget string
	for _, d := range p.Pairs {
		if !launcherReleaseTag.MatchString("role-images-"+d.OriginalRelease) || !launcherReleaseTag.MatchString("role-images-"+d.SourceApp) {
			return errors.New("invalid original/source commit")
		}
		// Validate constrained path fields before opening policy-named files.
		if !guidedName.MatchString(d.Role) || (d.Host != "darwin/arm64" && d.Host != "darwin/amd64" && d.Host != "linux/arm64" && d.Host != "linux/amd64") || (d.Platform != "linux/arm64" && d.Platform != "linux/amd64") {
			return errors.New("unsupported qualification platform")
		}
		if *published {
			if publishedTarget != "" && publishedTarget != d.TargetApp {
				return errors.New("review one published target per approval release")
			}
			publishedTarget = d.TargetApp
			report, err := readTesseraRegularFile(filepath.Join(*reports, d.AssetName()), upgrade.MaximumBytes, false)
			if err != nil {
				return fmt.Errorf("missing reviewed local qualification report: %w", err)
			}
			produced, err := generateReviewedPublishedUpgrade(d, report, assets.get)
			if err != nil {
				return err
			}
			for name, raw := range produced {
				if _, ok := files[name]; ok {
					return errors.New("duplicate upgrade pair or report")
				}
				files[name] = raw
			}
			continue
		}
		original, err := readTesseraRegularFile(filepath.Join(*originals, d.OriginalRelease+".json"), 1<<20, false)
		if err != nil {
			return err
		}
		target, err := readTesseraRegularFile(*images, 1<<20, false)
		if err != nil {
			return err
		}
		report, err := readTesseraRegularFile(filepath.Join(*reports, d.AssetName()), upgrade.MaximumBytes, false)
		if err != nil {
			return fmt.Errorf("missing executed qualification report: %w", err)
		}
		binary, err := readTesseraRegularFile(filepath.Join(*launchers, "relay-"+strings.ReplaceAll(d.Host, "/", "-")), 128<<20, false)
		if err != nil {
			return err
		}
		produced, err := generateUpgradeV2(d, launcherCommit(), original, target, report, binary)
		if err != nil {
			return err
		}
		for name, raw := range produced {
			if _, ok := files[name]; ok {
				return errors.New("duplicate upgrade pair or report")
			}
			files[name] = raw
		}
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	for name, raw := range files {
		if err := publishPublicInput(filepath.Join(*out, name), raw); err != nil {
			return err
		}
	}
	fmt.Printf("Generated %d v2 upgrade assets. No policy entry is inferred from version numbers.\n", len(files))
	return nil
}

// get must authenticate the exact repository, protected-main workflow, source
// commit and bytes. CI attests approval of reviewed local evidence, not execution
// of the Mac tests. Target binaries are downloaded, never rebuilt or republished.
func generateReviewedPublishedUpgrade(d upgrade.DeclarationV2, report []byte, get func(string, string) ([]byte, error)) (map[string][]byte, error) {
	if !launcherReleaseTag.MatchString("role-images-"+d.TargetApp) || d.Role != "coordinator" {
		return nil, errors.New("published approval requires an exact coordinator target")
	}
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(report)
	if err := d.Validate(); err != nil {
		return nil, err
	}
	q, err := upgrade.VerifyQualification(report, d)
	if err != nil {
		return nil, err
	}
	if !upgrade.IsCleanExitQualification(q.Schema) {
		return nil, errors.New("reviewed published approval requires completed-step qualification")
	}
	asset := "relay-" + strings.ReplaceAll(d.Host, "/", "-")
	for _, commit := range d.SafePredecessors {
		binary, err := get(commit, asset)
		if err != nil {
			return nil, err
		}
		if q.Predecessors[commit] != "sha256:"+upgradeBytesHash(binary) {
			return nil, errors.New("qualification used another predecessor executable")
		}
	}
	original, err := get(d.OriginalRelease, "relay-role-images.release.json")
	if err != nil {
		return nil, err
	}
	target, err := get(d.TargetApp, "relay-role-images.release.json")
	if err != nil {
		return nil, err
	}
	binary, err := get(d.TargetApp, asset)
	if err != nil {
		return nil, err
	}
	return generateUpgradeV2(d, d.TargetApp, original, target, report, binary)
}
