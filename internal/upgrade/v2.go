package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

const SchemaV2 = "relay-upgrade-compatibility/v2"

// OperatorTransitionSchema records a choice, never a compatibility certification.
// Older readers reject this schema instead of treating it as qualified evidence.
const OperatorTransitionSchema = "relay-operator-upgrade/v1"

func (d DeclarationV2) OperatorSelected() bool { return d.Schema == OperatorTransitionSchema }

// V2 authorizes one application transition over one original ceremony runtime.
// It deliberately does not authorize a cryptographic runtime migration.
type DeclarationV2 struct {
	Schema              string   `json:"schema"`
	OriginalRelease     string   `json:"original_release"`
	SourceApp           string   `json:"source_app"`
	TargetApp           string   `json:"target_app"`
	Role                string   `json:"role"`
	Host                string   `json:"host"`
	Platform            string   `json:"platform"`
	OriginalImage       string   `json:"original_image"`
	SigningImage        string   `json:"signing_image"`
	OnlineImage         string   `json:"online_image"`
	ProofToolSHA256     string   `json:"proof_tool_sha256"`
	Protocol            string   `json:"protocol"`
	StorageLayout       string   `json:"storage_layout"`
	ProfileSchema       string   `json:"profile_schema"`
	JournalSchema       string   `json:"journal_schema"`
	Adapters            []string `json:"adapters"`
	SafePredecessors    []string `json:"safe_predecessors"`
	QualificationSHA256 string   `json:"qualification_sha256"`
}

var adapterKinds = map[string]string{
	"inspect": "inspect-v1", "setup": "setup-retained-v1",
	"enrollment": "enrollment-retained-v4-v1", "grant": "grant-retained-v4-v1",
	"contribute": "participant-retained-v4-v1", "cleanup": "participant-retained-v4-v1",
	"download": "download-retained-v4-v1", "upload": "immutable-upload-v4-v1",
	"checkpoint": "checkpoint-cas-v4-v1", "lifecycle": "lifecycle-retained-v4-v1",
	"sign": "signature-retained-v4-v1", "verify": "verification-retained-v4-v1",
}

func Adapter(kind string) (string, error) {
	a, ok := adapterKinds[kind]
	if !ok {
		return "", fmt.Errorf("unsupported retained operation kind %q", kind)
	}
	return a, nil
}

func DecodeV2(raw []byte) (DeclarationV2, error) {
	var d DeclarationV2
	if err := decodeCanonical(raw, &d); err != nil {
		return d, err
	}
	return d, d.Validate()
}

func decodeCanonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return errors.New("invalid upgrade record size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing upgrade record")
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return errors.New("upgrade record must use canonical encoding without duplicate fields")
	}
	return nil
}

func validImage(value, role string) bool {
	prefix := "ghcr.io/zksecurity/relay/" + role + "@"
	return len(value) > len(prefix) && value[:len(prefix)] == prefix && digestPattern.MatchString(value[len(prefix):])
}

func (d DeclarationV2) Validate() error {
	if (d.Schema != SchemaV2 && !d.OperatorSelected()) || !commitPattern.MatchString(d.OriginalRelease) || !commitPattern.MatchString(d.SourceApp) || !commitPattern.MatchString(d.TargetApp) || d.SourceApp == d.TargetApp {
		return errors.New("invalid upgrade release transition")
	}
	if !slices.Contains([]string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}, d.Host) || !slices.Contains([]string{"linux/amd64", "linux/arm64"}, d.Platform) {
		return errors.New("unsupported upgrade host/platform")
	}
	imageRole := "relay-role-online"
	switch d.Role {
	case "coordinator", "auditor", "witness", "mirror", "upload-station":
		if !validImage(d.OnlineImage, "relay-role-online") {
			return errors.New("online runtime must be immutable")
		}
	case "participant":
		imageRole = "relay-ceremony-tool"
		if d.OnlineImage != "" {
			return errors.New("participant upgrade must retain its contributor image")
		}
	case "release-signer":
		imageRole = "relay-role-offline"
		if d.OnlineImage != "" {
			return errors.New("signer upgrade must retain its network-disabled image")
		}
	default:
		return errors.New("unsupported upgrade role")
	}
	if !validImage(d.OriginalImage, imageRole) || !validImage(d.SigningImage, "relay-role-offline") || !digestPattern.MatchString(d.ProofToolSHA256) {
		return errors.New("missing immutable runtime or qualification binding")
	}
	protocolSupported := d.Protocol == "proof-tool-mpc-ceremony-definition-v4" || ((d.Role == "coordinator" || d.Role == "release-signer") && d.Protocol == "proof-tool-mpc-ceremony-definition-v5")
	if !protocolSupported || d.StorageLayout != "storage-first-v2" || d.ProfileSchema != "relay-guided-role-v1" || d.JournalSchema != "relay-workflow-v4-state-v1" {
		return errors.New("unsupported upgrade format")
	}
	if d.OperatorSelected() {
		if d.QualificationSHA256 != "" || len(d.SafePredecessors) != 0 {
			return errors.New("operator selection must not claim qualification or safe predecessor coverage")
		}
	} else if !digestPattern.MatchString(d.QualificationSHA256) || len(d.SafePredecessors) == 0 || len(d.SafePredecessors) > 64 {
		return errors.New("missing or oversized compatibility evidence")
	}
	if len(d.Adapters) == 0 || len(d.Adapters) > len(adapterKinds) {
		return errors.New("missing or oversized compatibility coverage")
	}
	seen := map[string]bool{}
	for _, a := range d.Adapters {
		if seen[a] {
			return errors.New("duplicate recovery adapter")
		}
		seen[a] = true
		known := false
		for _, v := range adapterKinds {
			known = known || v == a
		}
		if !known {
			return errors.New("unknown recovery adapter")
		}
	}
	seen = map[string]bool{}
	for _, app := range d.SafePredecessors {
		if !commitPattern.MatchString(app) || seen[app] || app == d.TargetApp {
			return errors.New("invalid predecessor coverage")
		}
		seen[app] = true
	}
	if !d.OperatorSelected() && (!seen[d.SourceApp] || !seen[d.OriginalRelease]) {
		return errors.New("original and current applications need safe reentry coverage")
	}
	return nil
}

// Cover verifies inherited work, not merely work created by SourceApp. Runtime
// images are frozen; an adapter must explicitly cover every observed kind.
func (d DeclarationV2) Cover(priorApps, kinds []string) error {
	if err := d.Validate(); err != nil {
		return err
	}
	for _, app := range priorApps {
		if !d.OperatorSelected() && !slices.Contains(d.SafePredecessors, app) {
			return fmt.Errorf("no safe reentry coverage for %s", app)
		}
	}
	for _, kind := range kinds {
		a, err := Adapter(kind)
		if err != nil {
			return err
		}
		if !slices.Contains(d.Adapters, a) {
			return fmt.Errorf("no compatible recovery handler for %s", kind)
		}
	}
	return nil
}

func (d DeclarationV2) AssetName() string {
	return fmt.Sprintf("upgrade-v2-%s-%s-%s-%s-%s.json", d.OriginalRelease, d.SourceApp, d.Role, replaceSlash(d.Host), replaceSlash(d.Platform))
}
func replaceSlash(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] == '/' {
			out[i] = '-'
		}
	}
	return string(out)
}

type QualificationV2 struct {
	Schema          string            `json:"schema"`
	OriginalRelease string            `json:"original_release"`
	SourceApp       string            `json:"source_app"`
	TargetApp       string            `json:"target_app"`
	Role            string            `json:"role"`
	Host            string            `json:"host"`
	Platform        string            `json:"platform"`
	LauncherSHA256  string            `json:"launcher_sha256"`
	OnlineImage     string            `json:"online_image"`
	ProofToolSHA256 string            `json:"proof_tool_sha256"`
	OriginalImage   string            `json:"original_image"`
	SigningImage    string            `json:"signing_image"`
	Predecessors    map[string]string `json:"predecessor_launchers"`
	Passed          []string          `json:"passed"`
}

var QualificationChecks = []string{"full-journey", "mixed-versions", "retained-work", "activation-crashes", "execution-exclusion", "predecessor-reentry", "published-reconstruction"}

const CleanExitQualificationSchema = "relay-upgrade-qualification/v3"

// OnlineCleanExitQualificationSchema adds online runtime replacement without
// changing the native-only meaning of existing v3 reports.
const OnlineCleanExitQualificationSchema = "relay-upgrade-qualification/v4"

func IsCleanExitQualification(schema string) bool {
	return schema == CleanExitQualificationSchema || schema == OnlineCleanExitQualificationSchema
}

var OnlineCleanExitQualificationChecks = []string{"completed-step-continuation", "updater-interruption", "unsafe-update-refusal", "online-runtime-retry", "predecessor-reentry"}

var CleanExitQualificationChecks = []string{"completed-step-continuation", "updater-interruption", "unsafe-update-refusal"}

// V4 evidence exercises one original executable, not arbitrary retained versions.
func validateOnlineCleanExitScope(d DeclarationV2) error {
	if d.Role != "coordinator" || d.OnlineImage == d.OriginalImage {
		return errors.New("online completed-step qualification requires a changed coordinator online image")
	}
	if d.SourceApp != d.OriginalRelease || len(d.SafePredecessors) != 1 || d.SafePredecessors[0] != d.SourceApp {
		return errors.New("online completed-step qualification requires the first hop and exactly its original predecessor")
	}
	return nil
}

func VerifyQualification(raw []byte, d DeclarationV2) (QualificationV2, error) {
	var q QualificationV2
	if d.OperatorSelected() {
		return q, errors.New("operator selection is not qualification evidence")
	}
	if err := decodeCanonical(raw, &q); err != nil {
		return q, err
	}
	checks := QualificationChecks
	if q.Schema == CleanExitQualificationSchema {
		if d.Role != "coordinator" || d.OnlineImage != d.OriginalImage {
			return q, errors.New("clean-exit qualification only covers native-only coordinator updates")
		}
		checks = CleanExitQualificationChecks
	} else if q.Schema == OnlineCleanExitQualificationSchema {
		if err := validateOnlineCleanExitScope(d); err != nil {
			return q, err
		}
		checks = OnlineCleanExitQualificationChecks
	} else if q.Schema != "relay-upgrade-qualification/v2" {
		return q, errors.New("unknown qualification schema")
	}
	if q.OriginalRelease != d.OriginalRelease || q.SourceApp != d.SourceApp || q.TargetApp != d.TargetApp || q.Role != d.Role || q.Host != d.Host || q.Platform != d.Platform || q.OnlineImage != d.OnlineImage || q.ProofToolSHA256 != d.ProofToolSHA256 || !digestPattern.MatchString(q.LauncherSHA256) {
		return q, errors.New("qualification does not cover this exact application/runtime pair")
	}
	if q.OriginalImage != d.OriginalImage || q.SigningImage != d.SigningImage || len(q.Predecessors) != len(d.SafePredecessors) {
		return q, errors.New("qualification does not bind original images and every predecessor executable")
	}
	for _, commit := range d.SafePredecessors {
		if !digestPattern.MatchString(q.Predecessors[commit]) {
			return q, errors.New("qualification lacks a predecessor executable digest")
		}
	}
	if len(q.Passed) != len(checks) {
		return q, errors.New("unexpected qualification checks")
	}
	for _, check := range checks {
		if !slices.Contains(q.Passed, check) {
			return q, fmt.Errorf("missing qualification: %s", check)
		}
	}
	return q, nil
}
