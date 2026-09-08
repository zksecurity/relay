package main

// The release receipt records exact measured tools from an authenticated
// installation/image. Unlike legacy kit receipts it makes no compatibility-test
// or ceremony-mode claim. The signed ceremony still supplies the mode/policy.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const releaseToolReceiptSchema = "relay-release-tool-identities-v1"

type releaseToolReceipt struct {
	Schema       string `json:"schema"`
	SourceCommit string `json:"source_commit"`
	ProofCommit  string `json:"proof_commit"`
	Platform     string `json:"platform"`
	RelayPath    string `json:"relay_path"`
	RelaySHA256  string `json:"relay_sha256"`
	ProofPath    string `json:"proof_path"`
	ProofSHA256  string `json:"proof_sha256"`
}

func measuredReleaseTools(binary string) (releaseToolReceipt, error) {
	r := releaseToolReceipt{Schema: releaseToolReceiptSchema, SourceCommit: launcherCommit(), Platform: "linux/" + runtime.GOARCH}
	if !launcherReleaseTag.MatchString("role-images-" + r.SourceCommit) {
		return r, errors.New("release tool receipts require an identifiable release build")
	}
	a, commit, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		return r, err
	}
	r.ProofCommit = commit
	executable, err := os.Executable()
	if err != nil {
		return r, err
	}
	r.RelayPath, r.RelaySHA256, err = resolveAndHashExecutable(executable)
	if err != nil {
		return r, err
	}
	r.ProofPath, r.ProofSHA256, err = resolveAndHashExecutable(binary)
	if err != nil {
		return r, err
	}
	if r.ProofSHA256 != a.SHA256 {
		return r, errors.New("proof tool differs from this release's pinned architecture build")
	}
	return r, nil
}
func decodeReleaseToolReceipt(raw []byte) (toolIdentityReceipt, error) {
	var r releaseToolReceipt
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return toolIdentityReceipt{}, err
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return toolIdentityReceipt{}, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return toolIdentityReceipt{}, errors.New("release receipt must use the original canonical JSON")
	}
	if r.Schema != releaseToolReceiptSchema || r.SourceCommit != launcherCommit() || !launcherReleaseTag.MatchString("role-images-"+r.SourceCommit) {
		return toolIdentityReceipt{}, errors.New("tool receipt belongs to another source release")
	}
	a, commit, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		return toolIdentityReceipt{}, err
	}
	if r.ProofCommit != commit || r.Platform != "linux/"+runtime.GOARCH || r.ProofSHA256 != a.SHA256 || !sha256HexPattern.MatchString(r.RelaySHA256) {
		return toolIdentityReceipt{}, errors.New("tool receipt does not match the release's proof-tool pins")
	}
	relay := toolIdentity{VerifiedPath: r.RelayPath, Repository: "zksecurity/relay", Version: "role-images-" + r.SourceCommit, ReleaseID: "zksecurity/relay@role-images-" + r.SourceCommit, SHA256: r.RelaySHA256}
	proof := toolIdentity{VerifiedPath: r.ProofPath, Repository: "zksecurity/proof-tool", Version: "mpc-ci-" + commit, ReleaseID: "zksecurity/proof-tool@mpc-ci-" + commit, SHA256: r.ProofSHA256}
	if err := relay.validate("Relay"); err != nil {
		return toolIdentityReceipt{}, err
	}
	if err := proof.validate("proof-tool"); err != nil {
		return toolIdentityReceipt{}, err
	}
	return toolIdentityReceipt{Schema: r.Schema, Relay: relay, MPCCeremony: proof}, nil
}
func runInspectReleaseTools(args []string) error {
	if len(args) != 0 {
		return errors.New("inspect-tools takes no arguments")
	}
	r, err := measuredReleaseTools("/usr/local/bin/mpc-ceremony")
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}
func (p *rolePreparer) prepareToolReceipt() error {
	path := filepath.Join(p.d.Trust, "tool-identity-receipt.env")
	var r releaseToolReceipt
	if p.d.Role == "participant" {
		binary, err := prepareProofAsset(filepath.Join(p.d.Work, "approved-tools"), runtime.GOARCH)
		if err != nil {
			return err
		}
		r, err = measuredReleaseTools(binary.Path)
		if err != nil {
			return err
		}
		p.d.Values["binary"] = binary.Path
	} else {
		if p.d.Role == "release-signer" {
			return nil
		}
		profile, err := p.profile(p.d.Role)
		if err != nil {
			return err
		}
		client := osDockerCommandClient{binary: "docker"}
		_, endpoint, err := resolveDockerEndpoint(client)
		if err != nil {
			return err
		}
		if err := validateLocalDockerEndpoint(endpoint); err != nil {
			return err
		}
		args := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit=core=0:0", "--platform", profile.Platform, "--entrypoint=/usr/local/bin/relay", profile.Image, "ceremony", "inspect-tools"}
		raw, stderr, err := client.BindHost(endpoint).Output(args...)
		if err != nil {
			return fmt.Errorf("inspect approved image tools: %w: %s", err, stderr)
		}
		if len(raw) > maxToolIdentityReceipt {
			return errors.New("image tool receipt too large")
		}
		if _, err := decodeReleaseToolReceipt(raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.RelayPath != "/usr/local/bin/relay" || r.ProofPath != "/usr/local/bin/mpc-ceremony" {
			return errors.New("unexpected release image tool paths")
		}
	}
	if r.SourceCommit != strings.TrimPrefix(p.d.Release, "role-images-") {
		return errors.New("prepared tools differ from selected release")
	}
	if _, err := os.Lstat(path); err == nil {
		var existing releaseToolReceipt
		if err := setupReadJSON(path, &existing); err != nil {
			return err
		}
		if existing != r {
			return errors.New("existing tool receipt differs; preserve it and review before changing the installation")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeJSONNoReplace(path, r, 0600); err != nil {
		return err
	}
	return p.save()
}
