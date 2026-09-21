// Package upgrade validates release-declared compatibility. It does not verify
// provenance or activate software; callers must authenticate declarations first.
package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const Schema = "relay-upgrade-compatibility/v1"
const MaximumBytes = 64 << 10

var commitPattern = regexp.MustCompile("^[0-9a-f]{40}$")
var digestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var onlinePattern = regexp.MustCompile("^ghcr.io/zksecurity/relay/relay-role-online@sha256:[0-9a-f]{64}$")

// Declaration authorizes one specific source-to-target combination, not all
// builds that happen to understand the same JSON format.
type Declaration struct {
	Schema                string `json:"schema"`
	SourceRelease         string `json:"source_release"`
	TargetRelease         string `json:"target_release"`
	Role                  string `json:"role"`
	Platform              string `json:"platform"`
	ProfileSchema         string `json:"profile_schema"`
	WorkflowSchema        string `json:"workflow_schema"`
	SourceOnlineImage     string `json:"source_online_image"`
	TargetOnlineImage     string `json:"target_online_image"`
	ProofToolSHA256       string `json:"proof_tool_sha256"`
	OldVersionReentrySafe bool   `json:"old_version_reentry_safe"`
}

// Decode accepts bounded, known fields only. Authentication of the original
// exact bytes is a separate prerequisite, never implied by successful parsing.
func Decode(raw []byte) (Declaration, error) {
	var d Declaration
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return d, errors.New("invalid compatibility declaration size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Declaration{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Declaration{}, errors.New("trailing compatibility declaration data")
	}
	// Require the producer's deterministic encoding. This also rejects duplicate
	// keys, which encoding/json otherwise silently accepts.
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return Declaration{}, errors.New("compatibility declaration must use canonical field encoding")
	}
	return d, d.Validate()
}

func (d Declaration) Validate() error {
	if d.Schema != Schema || !commitPattern.MatchString(d.SourceRelease) || !commitPattern.MatchString(d.TargetRelease) || d.SourceRelease == d.TargetRelease {
		return errors.New("invalid compatibility release pair")
	}
	// Initial scope: online coordinator changes with unchanged local formats.
	// Participant and signer upgrades require their separate runtime mappings.
	if d.Role != "coordinator" || (d.Platform != "linux/amd64" && d.Platform != "linux/arm64") ||
		d.ProfileSchema != "relay-guided-role-v1" || d.WorkflowSchema != "relay-workflow-v4-state-v1" {
		return errors.New("unsupported compatibility scope")
	}
	if !onlinePattern.MatchString(d.SourceOnlineImage) || !onlinePattern.MatchString(d.TargetOnlineImage) || !digestPattern.MatchString(d.ProofToolSHA256) {
		return errors.New("compatibility requires immutable online images and a proof-tool digest")
	}
	if !d.OldVersionReentrySafe {
		return errors.New("upgrade requires safe old-version reentry")
	}
	return nil
}

// Installation is measured from independently verified release assets and the
// in-image executable, never copied from a declaration and treated as evidence.
type Installation struct {
	Release         string
	OnlineImage     string
	ProofToolSHA256 string
}

func (d Declaration) Match(source, target Installation) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if source.Release != d.SourceRelease || target.Release != d.TargetRelease ||
		source.OnlineImage != d.SourceOnlineImage || target.OnlineImage != d.TargetOnlineImage ||
		source.ProofToolSHA256 != d.ProofToolSHA256 || target.ProofToolSHA256 != d.ProofToolSHA256 {
		return errors.New("installed release/runtime does not match compatibility declaration")
	}
	return nil
}
