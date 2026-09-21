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

// Entries are reviewed release policy, not inferred from matching version
// strings. Empty policy means no source release is authorized for upgrades.
type upgradeSourcePolicy struct {
	Schema  string `json:"schema"`
	Sources []struct {
		Release               string `json:"release"`
		Platform              string `json:"platform"`
		OnlineImage           string `json:"online_image"`
		ProofToolSHA256       string `json:"proof_tool_sha256"`
		OldVersionReentrySafe bool   `json:"old_version_reentry_safe"`
	} `json:"sources"`
}

func generateUpgradeDeclarations(policy upgradeSourcePolicy, target string, releaseMap, proofInputs []byte) (map[string][]byte, error) {
	if policy.Schema != "relay-upgrade-sources/v1" || policy.Sources == nil || !launcherReleaseTag.MatchString("role-images-"+target) {
		return nil, errors.New("invalid upgrade source policy")
	}
	var inputs struct {
		MPC map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"mpc"`
	}
	if err := json.Unmarshal(proofInputs, &inputs); err != nil {
		return nil, err
	}
	result := map[string][]byte{}
	for _, source := range policy.Sources {
		image, err := selectReleaseImage(releaseMap, target, "coordinator", source.Platform)
		if err != nil {
			return nil, err
		}
		proof := "sha256:" + inputs.MPC[strings.ReplaceAll(source.Platform, "/", "_")].SHA256
		if proof != source.ProofToolSHA256 {
			return nil, errors.New("reviewed source uses a different proof-tool; upgrade not authorized")
		}
		d := upgrade.Declaration{Schema: upgrade.Schema, SourceRelease: source.Release, TargetRelease: target, Role: "coordinator", Platform: source.Platform, ProfileSchema: guidedSchema, WorkflowSchema: workflowV4JournalSchema, SourceOnlineImage: source.OnlineImage, TargetOnlineImage: image, ProofToolSHA256: proof, OldVersionReentrySafe: source.OldVersionReentrySafe}
		if err := d.Validate(); err != nil {
			return nil, err
		}
		name := fmt.Sprintf("upgrade-%s-coordinator-%s.json", source.Release, strings.TrimPrefix(source.Platform, "linux/"))
		if _, ok := result[name]; ok {
			return nil, errors.New("duplicate compatibility pair")
		}
		raw, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		result[name] = raw
	}
	return result, nil
}

func runUpgradeManifests(args []string) error {
	f := flag.NewFlagSet("ceremony upgrade-manifests", flag.ContinueOnError)
	sources := f.String("sources", "", "reviewed source policy")
	images := f.String("role-images", "", "target release map")
	inputs := f.String("proof-inputs", "", "target proof-tool pins")
	out := f.String("out", "", "fresh output directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *out == "" {
		return errors.New("fresh output directory required")
	}
	var policy upgradeSourcePolicy
	if err := setupReadJSON(*sources, &policy); err != nil {
		return err
	}
	m, err := readTesseraRegularFile(*images, 1<<20, false)
	if err != nil {
		return err
	}
	p, err := readTesseraRegularFile(*inputs, 1<<20, false)
	if err != nil {
		return err
	}
	files, err := generateUpgradeDeclarations(policy, launcherCommit(), m, p)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	for name, raw := range files {
		if err := publishPublicInput(filepath.Join(*out, name), raw); err != nil {
			return err
		}
	}
	fmt.Printf("Generated %d compatibility declarations. Empty policy authorizes no upgrades.\n", len(files))
	return nil
}
