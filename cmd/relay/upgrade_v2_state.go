package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"github.com/zksecurity/relay/internal/upgrade"
)

const upgradeSelectionV2Schema = "relay-application-selection/v2"

type upgradeSelectionV2 struct {
	Schema          string            `json:"schema"`
	Previous        string            `json:"previous"`
	Declaration     []byte            `json:"declaration"`
	OriginalMap     []byte            `json:"original_map"`
	TargetMap       []byte            `json:"target_map"`
	Qualification   []byte            `json:"qualification"`
	Profile         guidedProfile     `json:"profile"`
	SettingsRoot    string            `json:"settings_root"`
	Bindings        map[string]string `json:"bindings"`
	Launcher        string            `json:"launcher"`
	LauncherSHA256  string            `json:"launcher_sha256"`
	StartPath       string            `json:"start_path"`
	PreviousStart   []byte            `json:"previous_start"`
	InventorySHA256 string            `json:"inventory_sha256"`
	Kinds           []string          `json:"kinds"`
	Setup           *upgradeSetupV2   `json:"setup,omitempty"`
	ApprovalRelease string            `json:"approval_release,omitempty"`
}

type upgradeV2Pointer struct {
	Schema     string `json:"schema"`
	Generation string `json:"generation"`
}

func upgradeV2Root(work string) string { return filepath.Join(work, ".relay-upgrades") }
func upgradeV2PointerPath(work string) string {
	return filepath.Join(upgradeV2Root(work), "active.json")
}
func upgradeBytesHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func upgradeV2ReadHistory(work string) ([]upgradeSelectionV2, string, error) {
	if work == "" {
		return nil, "", nil
	}
	if err := validateCommitLocalPath(work); err != nil {
		return nil, "", err
	}
	var p upgradeV2Pointer
	if err := readWorkflowV4JSON(upgradeV2PointerPath(work), &p); errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	} else if err != nil {
		return nil, "", err
	}
	if p.Schema != "relay-application-pointer/v2" {
		return nil, "", errors.New("unknown application selection pointer")
	}
	current := p.Generation
	seen := map[string]bool{}
	var history []upgradeSelectionV2
	for current != "" {
		if len(history) >= 64 || len(current) != 64 || seen[current] {
			return nil, "", errors.New("invalid application selection history")
		}
		if _, err := hex.DecodeString(current); err != nil {
			return nil, "", err
		}
		seen[current] = true
		file := filepath.Join(upgradeV2Root(work), "generations", current+".json")
		raw, err := readTesseraRegularFile(file, workflowV4MaximumBytes, true)
		if err != nil {
			return nil, "", err
		}
		if upgradeBytesHash(raw) != current {
			return nil, "", errors.New("application selection bytes changed")
		}
		var s upgradeSelectionV2
		if err := readWorkflowV4JSON(file, &s); err != nil {
			return nil, "", err
		}
		if s.Schema != upgradeSelectionV2Schema || s.Profile.Work != work {
			return nil, "", errors.New("selection belongs to another workspace")
		}
		if _, err := upgrade.DecodeV2(s.Declaration); err != nil {
			return nil, "", err
		}
		d, _ := upgrade.DecodeV2(s.Declaration)
		if _, err := upgradeApprovalCommit(s.ApprovalRelease, d.TargetApp); err != nil {
			return nil, "", err
		}
		if !upgradeV2ProfileMatches(s.Profile, s.Profile, d) {
			return nil, "", errors.New("selection history changed its frozen role")
		}
		history = append(history, s)
		current = s.Previous
	}
	if len(history) == 0 {
		return nil, "", errors.New("empty application selection history")
	}
	for i, s := range history {
		d, _ := upgrade.DecodeV2(s.Declaration)
		if i+1 < len(history) {
			old, _ := upgrade.DecodeV2(history[i+1].Declaration)
			if d.SourceApp != old.TargetApp || d.OriginalRelease != old.OriginalRelease || d.Role != old.Role || d.Host != old.Host || d.Platform != old.Platform || !upgradeV2FrozenProfileEqual(s.Profile, history[i+1].Profile) || !reflect.DeepEqual(s.Bindings, history[i+1].Bindings) || !reflect.DeepEqual(s.Setup, history[i+1].Setup) {
				return nil, "", errors.New("broken application selection lineage")
			}
		}
		if i+1 == len(history) && d.SourceApp != d.OriginalRelease {
			return nil, "", errors.New("first selection must bind original application")
		}
		var prior []string
		for _, older := range history[i+1:] {
			od, _ := upgrade.DecodeV2(older.Declaration)
			prior = append(prior, od.TargetApp, od.SourceApp)
		}
		if err := d.Cover(prior, s.Kinds); err != nil {
			return nil, "", err
		}
	}
	return history, p.Generation, nil
}

func upgradeV2ProfileMatches(p, original guidedProfile, d upgrade.DeclarationV2) bool {
	if d.Role != original.Role || d.Platform != original.Platform || d.OriginalRelease != original.ReleaseCommit {
		return false
	}
	if p.Role == "keygen" && p.Work == original.Keys && p.Keys == "" && p.ReleaseCommit == original.ReleaseCommit && p.Platform == original.Platform {
		return p.Image == d.SigningImage
	}
	if p.ReleaseCommit != original.ReleaseCommit || p.Work != original.Work || p.Trust != original.Trust || p.Keys != original.Keys || p.Platform != original.Platform {
		return false
	}
	// Named actions and network-disabled child profiles share the exact frozen
	// mount roots; commands remain subject to their ordinary action validation.
	if p.Role == "decision-signer" || p.Role == "keygen" {
		return p.Image == d.SigningImage
	}
	return p.Role == original.Role && p.Image == d.OriginalImage && p.Config == original.Config && (p.Name == original.Name || len(p.Command) > 0)
}

// Credential references may be rotated by the existing credential workflow.
// They are never copied into compatibility authority or used to infer identity.
func upgradeV2FrozenProfileEqual(a, b guidedProfile) bool {
	a.Credentials, a.R2Parent, a.R2Control, a.UpgradeOnlineImage = "", "", "", ""
	b.Credentials, b.R2Parent, b.R2Control, b.UpgradeOnlineImage = "", "", "", ""
	return reflect.DeepEqual(a, b)
}

func upgradeV2Selected(p guidedProfile, settingsRoot string, checkExecutable bool) (upgradeSelectionV2, upgrade.DeclarationV2, bool, error) {
	var zero upgradeSelectionV2
	var zd upgrade.DeclarationV2
	selectionWork, err := upgradeV2SelectionWork(p)
	if err != nil {
		return zero, zd, false, err
	}
	history, _, err := upgradeV2ReadHistory(selectionWork)
	if err != nil {
		return zero, zd, false, err
	}
	if len(history) == 0 {
		return zero, zd, false, nil
	}
	s := history[0]
	d, err := upgrade.DecodeV2(s.Declaration)
	if err != nil {
		return zero, zd, false, err
	}
	if s.SettingsRoot != settingsRoot || d.Host != runtime.GOOS+"/"+runtime.GOARCH || !upgradeV2ProfileMatches(p, s.Profile, d) {
		return zero, zd, false, errors.New("application update does not match this role, host or frozen runtime")
	}
	if d.TargetApp != launcherCommit() {
		return zero, zd, false, errors.New("use the active updated launcher from start.sh; an older app is not selected")
	}
	for _, item := range []struct {
		raw                 []byte
		commit, role, image string
	}{{s.OriginalMap, d.OriginalRelease, s.Profile.Role, d.OriginalImage}, {s.OriginalMap, d.OriginalRelease, "decision-signer", d.SigningImage}} {
		image, err := selectReleaseImage(item.raw, item.commit, item.role, d.Platform)
		if err != nil || image != item.image {
			return zero, zd, false, errors.New("cached original release map changed")
		}
	}
	if d.OnlineImage != "" {
		image, err := upgradeV2DeclaredOnlineImage(s.OriginalMap, s.TargetMap, d)
		if err != nil || image != d.OnlineImage {
			return zero, zd, false, errors.New("cached target release map changed")
		}
	}
	if "sha256:"+upgradeBytesHash(s.Qualification) != d.QualificationSHA256 {
		return zero, zd, false, errors.New("qualification report bytes changed")
	}
	q, err := upgrade.VerifyQualification(s.Qualification, d)
	if err != nil || q.LauncherSHA256 != "sha256:"+s.LauncherSHA256 {
		return zero, zd, false, errors.New("qualification does not cover the selected executable")
	}
	if (len(s.Bindings) == 0 && s.Setup == nil) || s.StartPath != filepath.Join(filepath.Dir(s.Profile.Work), "start.sh") {
		return zero, zd, false, errors.New("missing frozen inputs or invalid entry point")
	}
	if err := upgradeV2CheckDraft(s); err != nil {
		return zero, zd, false, err
	}
	if s.Setup != nil {
		if err := upgradeV2SetupManifest(s.Setup.Manifest, s.OriginalMap, d.OriginalRelease, d.Platform, d.ProofToolSHA256); err != nil {
			return zero, zd, false, err
		}
	}
	for path, want := range s.Bindings {
		got, err := setupFileHash(path)
		if err != nil || got != want {
			return zero, zd, false, fmt.Errorf("frozen ceremony input changed: %s", filepath.Base(path))
		}
	}
	if checkExecutable {
		exe, err := os.Executable()
		if err != nil {
			return zero, zd, false, err
		}
		h, err := setupFileHash(exe)
		if err != nil || h != s.LauncherSHA256 {
			return zero, zd, false, errors.New("running executable differs from attested selection")
		}
	}
	return s, d, true, nil
}

func upgradeV2Activate(s upgradeSelectionV2, expected string) error {
	if s.Schema != upgradeSelectionV2Schema {
		return errors.New("invalid application selection schema")
	}
	d, err := upgrade.DecodeV2(s.Declaration)
	if err != nil {
		return err
	}
	if _, err := upgradeApprovalCommit(s.ApprovalRelease, d.TargetApp); err != nil {
		return err
	}
	if s.Setup != nil {
		if err := upgradeV2SetupManifest(s.Setup.Manifest, s.OriginalMap, d.OriginalRelease, d.Platform, d.ProofToolSHA256); err != nil {
			return err
		}
	}
	if d.OriginalRelease != s.Profile.ReleaseCommit || !upgradeV2ProfileMatches(s.Profile, s.Profile, d) {
		return errors.New("selection does not bind original profile")
	}
	q, err := upgrade.VerifyQualification(s.Qualification, d)
	if err != nil {
		return err
	}
	if "sha256:"+upgradeBytesHash(s.Qualification) != d.QualificationSHA256 || q.LauncherSHA256 != "sha256:"+s.LauncherSHA256 {
		return errors.New("selection qualification mismatch")
	}
	for _, item := range []struct {
		raw                 []byte
		commit, role, image string
	}{
		{s.OriginalMap, d.OriginalRelease, d.Role, d.OriginalImage},
		{s.OriginalMap, d.OriginalRelease, "decision-signer", d.SigningImage},
	} {
		image, err := selectReleaseImage(item.raw, item.commit, item.role, d.Platform)
		if err != nil || image != item.image {
			return errors.New("activation release map mismatch")
		}
	}
	if d.OnlineImage != "" {
		image, err := upgradeV2DeclaredOnlineImage(s.OriginalMap, s.TargetMap, d)
		if err != nil || image != d.OnlineImage {
			return errors.New("activation target map mismatch")
		}
	}
	if (len(s.Bindings) == 0 && s.Setup == nil) || s.StartPath != filepath.Join(filepath.Dir(s.Profile.Work), "start.sh") {
		return errors.New("activation has no frozen bindings or invalid start path")
	}
	if s.Previous != expected {
		return errors.New("selection predecessor differs from reviewed plan")
	}
	history, current, err := upgradeV2ReadHistory(s.Profile.Work)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("application selection changed; review again")
	}
	source, apps, err := upgradeV2Source(s.Profile)
	if err != nil {
		return err
	}
	if d.SourceApp != source {
		return errors.New("selection skips the active application")
	}
	if len(history) > 0 && !upgradeV2FrozenProfileEqual(s.Profile, history[0].Profile) {
		return errors.New("original profile changed")
	}
	if len(history) > 0 && !reflect.DeepEqual(s.Bindings, history[0].Bindings) {
		return errors.New("frozen input bindings changed; previous selection retained")
	}
	if len(history) > 0 && !reflect.DeepEqual(s.Setup, history[0].Setup) {
		return errors.New("setup descriptor changed")
	}
	if err := d.Cover(apps, s.Kinds); err != nil {
		return err
	}
	if upgrade.IsCleanExitQualification(q.Schema) {
		if err := upgradeRequireCleanExit(s, d, q.Schema); err != nil {
			return err
		}
		inv, err := upgradeV2Inventory(s.Profile, d)
		if err != nil {
			return err
		}
		if inv.digest() != s.InventorySHA256 {
			return errors.New("retained work changed during update review; nothing selected")
		}
	}
	root := upgradeV2Root(s.Profile.Work)
	if err := ensurePrivateDirectory(root); err != nil {
		return err
	}
	if s.Setup != nil {
		if err := upgradeV2PrepareSetupState(s, len(history) == 0); err != nil {
			return err
		}
		if err := upgradeV2CheckDraft(s); err != nil {
			return err
		}
	}
	if err := ensurePrivateDirectory(filepath.Join(root, "generations")); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	hash := upgradeBytesHash(raw)
	if len(raw) > workflowV4MaximumBytes {
		return errors.New("application selection exceeds size limit")
	}
	if err := publishPublicInput(filepath.Join(root, "generations", hash+".json"), raw); err != nil {
		return err
	}
	// Caller owns the workspace lock; compare again before atomic publication.
	_, current, err = upgradeV2ReadHistory(s.Profile.Work)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("application selection changed during activation")
	}
	return saveJSONAtomicWithLimit(upgradeV2PointerPath(s.Profile.Work), upgradeV2Pointer{"relay-application-pointer/v2", hash}, workflowV4MaximumBytes)
}

func upgradeV2RoleKinds(role string) []string {
	base := []string{"inspect", "setup", "enrollment", "sign", "verify"}
	switch role {
	case "coordinator":
		return append(base, "grant", "download", "upload", "checkpoint", "lifecycle")
	case "participant":
		return append(base, "contribute", "cleanup", "download", "upload")
	case "release-signer", "auditor", "upload-station", "witness", "mirror":
		return append(base, "download", "upload", "lifecycle")
	}
	return nil
}

func upgradeV2Source(p guidedProfile) (string, []string, error) {
	history, _, err := upgradeV2ReadHistory(p.Work)
	if err != nil {
		return "", nil, err
	}
	apps := []string{p.ReleaseCommit}
	source := p.ReleaseCommit
	for i, s := range history {
		d, err := upgrade.DecodeV2(s.Declaration)
		if err != nil {
			return "", nil, err
		}
		if i == 0 {
			source = d.TargetApp
		}
		apps = append(apps, d.TargetApp, d.SourceApp)
	}
	slices.Sort(apps)
	apps = slices.Compact(apps)
	return source, apps, nil
}

func upgradeV2Resolve(p guidedProfile, settingsRoot string) (guidedProfile, bool, error) {
	_, d, found, err := upgradeV2Selected(p, settingsRoot, true)
	if err != nil || !found {
		return p, found, err
	}
	p.UpgradeOnlineImage = "" // proof and signer invocation always keep original
	if p.Role == d.Role && d.OnlineImage != "" {
		p.UpgradeOnlineImage = d.OnlineImage
	}
	return p, true, nil
}

func upgradeV2BindingFiles(p guidedProfile) (map[string]string, error) {
	files := []string{filepath.Join(p.Work, "ceremony/public/ceremony.json"), filepath.Join(p.Work, "ceremony/public/ceremony.sig"), filepath.Join(p.Work, "ceremony/config/relay-storage.json")}
	if p.Role != "upload-station" {
		files = append(files, filepath.Join(p.Keys, "identity.json"))
	}
	key := "coordinator-public-key.hex"
	if p.Role == "coordinator" {
		key = "setup-coordinator.hex"
	}
	files = append(files, filepath.Join(p.Trust, key))
	out := map[string]string{}
	for _, file := range files {
		h, err := setupFileHash(file)
		if err != nil {
			return nil, err
		}
		out[file] = h
	}
	return out, nil
}

func upgradeV2WriteStart(s upgradeSelectionV2) error {
	p := s.Profile
	generated := upgradeV2GeneratedStart(s.PreviousStart, p)
	history, _, err := upgradeV2ReadHistory(p.Work)
	if err != nil {
		return err
	}
	for _, old := range history {
		v := ceremonyUpgradeSelection{Launcher: old.Launcher, SettingsRoot: old.SettingsRoot}
		generated = generated || string(s.PreviousStart) == string(upgradeStartBytes(v, old.Profile))
		generated = generated || string(s.PreviousStart) == string(upgradeV2StartBytes(old))
	}
	if len(history) == 0 || !reflect.DeepEqual(s, history[0]) {
		return errors.New("entry-point repair does not match active selection")
	}
	if !generated {
		return errors.New("custom start script preserved; use the explicit resume command")
	}
	v1 := ceremonyUpgradeSelection{Launcher: s.Launcher, SettingsRoot: s.SettingsRoot, StartPath: s.StartPath, PreviousStart: s.PreviousStart}
	// Reuse atomic script installation, but preserve the actual role.
	return upgradeInstallStartBytes(v1, p, upgradeV2StartBytes(s))
}

// Keep the installer's setup/resume entry point. Replacing it with `guide`
// would bypass unfinished onboarding even for an initialized ceremony.
func upgradeV2StartBytes(s upgradeSelectionV2) []byte {
	if upgradeV2GeneratedStart(s.PreviousStart, s.Profile) {
		lines := strings.Split(string(s.PreviousStart), "\n")
		lines[2] = "relay_launcher='" + strings.ReplaceAll(s.Launcher, "'", "'\\''") + "'"
		return []byte(strings.Join(lines, "\n"))
	}
	return upgradeStartBytes(ceremonyUpgradeSelection{Launcher: s.Launcher, SettingsRoot: s.SettingsRoot}, s.Profile)
}

// Recognize only the exact installer template or our own generated guide
// template. Do not evaluate shell or overwrite additional operator commands.
func upgradeV2GeneratedStart(raw []byte, p guidedProfile) bool {
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 4 && lines[0] == "#!/usr/bin/env bash" && lines[1] == "set -euo pipefail" && lines[3] == "" {
		// Previously generated entry points are accepted by exact reconstruction
		// by the caller through selection history, not arbitrary exec scripts.
		return false
	}
	if len(lines) != 14 || lines[0] != "#!/usr/bin/env bash" || lines[1] != "set -euo pipefail" || !strings.HasPrefix(lines[2], "relay_launcher='") || !strings.HasSuffix(lines[2], "'") {
		return false
	}
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	value := strings.TrimPrefix(lines[2], "relay_launcher=")
	decoded := strings.ReplaceAll(value[1:len(value)-1], "'\\''", "'")
	if quote(decoded) != value || !filepath.IsAbs(decoded) || filepath.Clean(decoded) != decoded {
		return false
	}
	want := []string{"ceremony_name=" + quote(p.Name), "ceremony_role=" + quote(p.Role), "ceremony_release=" + quote("role-images-"+p.ReleaseCommit), "ceremony_work=" + quote(p.Work), "ceremony_trust=" + quote(p.Trust), "ceremony_keys=" + quote(p.Keys), `if [[ "$ceremony_role" == coordinator ]]; then`, `  exec "$relay_launcher" coordinator prepare --name "$ceremony_name" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, `fi`, `exec "$relay_launcher" ceremony prepare --name "$ceremony_name" --role "$ceremony_role" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, ""}
	return reflect.DeepEqual(lines[3:], want)
}

func upgradeV2KindForOperation(kind string) (string, error) {
	switch kind {
	case "contribute":
		return "contribute", nil
	case "attest-erasure":
		return "cleanup", nil
	case "download-outbound", "download-receipt", "download-candidate":
		return "download", nil
	case "upload-receipt", "upload-candidate":
		return "upload", nil
	case "issue-grant":
		return "grant", nil
	case "sign-receipt", "sign-return", "sign-return-receipt":
		return "sign", nil
	case "commit-outbound", "commit-receipt", "commit-candidate":
		return "checkpoint", nil
	}
	return "", errors.New("unrecognized retained operation: " + strings.TrimSpace(kind))
}
