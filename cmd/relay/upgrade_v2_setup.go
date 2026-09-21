package main

// Setup has stable installation settings, but not yet a signed ceremony. Its
// commitments grow in separate atomic groups; an upgrade never invents a
// successful setup result merely because output files exist.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type upgradeSetupV2 struct {
	Draft    string   `json:"draft"`
	Manifest []byte   `json:"original_software_manifest"`
	Absent   []string `json:"initially_absent"`
}
type upgradeSetupStateV2 struct {
	Schema string                       `json:"schema"`
	Owner  guidedProfile                `json:"owner"`
	Groups map[string]map[string]string `json:"groups"`
}

func upgradeV2DraftProfile(work, name, role string) (guidedProfile, *upgradeSetupV2, error) {
	var p guidedProfile
	if err := validateRoleMount(work, false); err != nil {
		return p, nil, err
	}
	p.Schema, p.Name, p.Role, p.Work = guidedSchema, name, role, work
	path := filepath.Join(work, "role-preparation/draft.json")
	if role == "coordinator" {
		path = filepath.Join(work, "coordinator-setup/draft.json")
	}
	if st, err := os.Lstat(path); err != nil {
		return p, nil, err
	} else if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return p, nil, errors.New("setup draft must be a protected regular file")
	}
	if role == "coordinator" {
		var d coordinatorDraft
		if err := setupReadJSON(path, &d); err != nil {
			return p, nil, err
		}
		if d.Name != name || d.Work != work || d.Schema != "relay-coordinator-draft-v1" {
			return p, nil, errors.New("draft does not match this installation")
		}
		if d.Tessera != nil || d.TesseraSetup != nil || d.TesseraSetupV3 != nil || d.TesseraExportPath != "" {
			return p, nil, errors.New("Tessera-linked setup upgrades are not qualified")
		}
		if d.Status != "draft" && d.Status != "initialization-attempted" && d.Status != "definition-verified" {
			return p, nil, errors.New("unknown setup status")
		}
		p.ReleaseCommit = strings.TrimPrefix(d.Release, "role-images-")
		p.Trust, p.Keys = d.Trust, d.Keys
		p.Credentials, p.R2Parent, p.R2Control = d.Credentials, d.R2Parent, d.R2Control
	} else {
		var d rolePreparation
		if err := setupReadJSON(path, &d); err != nil {
			return p, nil, err
		}
		if d.Schema != "relay-role-preparation-v1" || d.Name != name || d.Role != role || d.Work != work {
			return p, nil, errors.New("role preparation does not match this installation")
		}
		p.ReleaseCommit = strings.TrimPrefix(d.Release, "role-images-")
		p.Trust, p.Keys = d.Trust, d.Keys
		if role == "participant" {
			p.Config = filepath.Join(work, "ceremony/config/participant-phase1.json")
		}
	}
	if !launcherReleaseTag.MatchString("role-images-" + p.ReleaseCommit) {
		return p, nil, errors.New("draft has no exact original release")
	}
	for _, path := range []string{p.Trust, p.Keys} {
		if err := validateRoleMount(path, false); err != nil {
			return p, nil, err
		}
	}
	platform, err := machineDockerPlatform()
	if err != nil {
		return p, nil, err
	}
	p.Platform = platform
	return p, &upgradeSetupV2{Draft: path}, nil
}

func upgradeV2CheckDraft(s upgradeSelectionV2) error {
	if s.Setup == nil {
		return nil
	}
	p, setup, err := upgradeV2DraftProfile(s.Profile.Work, s.Profile.Name, s.Profile.Role)
	if err != nil {
		return err
	}
	p.Image = s.Profile.Image
	// Credentials may legitimately change. No other installation setting may.
	if setup.Draft != s.Setup.Draft || !upgradeV2FrozenProfileEqual(p, s.Profile) {
		return errors.New("setup installation settings changed")
	}
	_, err = upgradeV2ReadSetupState(s)
	return err
}

func upgradeV2SetupStatePath(work string) string {
	return filepath.Join(upgradeV2Root(work), "setup-state.json")
}

func upgradeV2ReadSetupState(s upgradeSelectionV2) (upgradeSetupStateV2, error) {
	var state upgradeSetupStateV2
	if err := readWorkflowV4JSON(upgradeV2SetupStatePath(s.Profile.Work), &state); err != nil {
		return state, err
	}
	if state.Schema != "relay-upgrade-setup-bindings/v1" || !upgradeV2FrozenProfileEqual(state.Owner, s.Profile) || state.Groups == nil {
		return state, errors.New("setup binding history missing or belongs to another installation")
	}
	for kind, files := range state.Groups {
		if err := upgradeV2ValidateSetupGroup(s.Profile, kind, files); err != nil {
			return state, err
		}
		for path, want := range files {
			got, err := setupFileHash(path)
			if err != nil || got != want {
				return state, errors.New("previously retained setup input changed")
			}
		}
	}
	return state, nil
}

func upgradeV2CaptureFiles(files ...string) (map[string]string, error) {
	result := map[string]string{}
	for _, path := range files {
		h, err := setupFileHash(path)
		if err != nil {
			return nil, err
		}
		result[path] = h
	}
	return result, nil
}

// Caller owns the setup/workspace lock, and has actually authenticated the
// exact captured bytes for definition/storage groups. Retry reauthenticates;
// it does not repeat identity generation or initialization.
func upgradeV2RecordSetupGroup(work, kind string, files map[string]string) error {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return err
	}
	if len(history) == 0 || history[0].Setup == nil {
		return nil
	}
	lock, err := acquireParticipantRunLock("", filepath.Join(upgradeV2Root(work), "setup-activity"))
	if err != nil {
		return err
	}
	defer lock.release()
	s := history[0]
	if err := upgradeV2ValidateSetupGroup(s.Profile, kind, files); err != nil {
		return err
	}
	state, err := upgradeV2ReadSetupState(s)
	if err != nil {
		return err
	}
	for path, want := range files {
		got, err := setupFileHash(path)
		if err != nil || got != want {
			return errors.New("setup files changed during verification")
		}
	}
	if old, ok := state.Groups[kind]; ok {
		if !reflect.DeepEqual(old, files) {
			return errors.New("cannot replace a committed setup group")
		}
		return nil
	}
	state.Groups[kind] = files
	return saveJSONAtomicWithLimit(upgradeV2SetupStatePath(work), state, workflowV4MaximumBytes)
}

func upgradeV2ValidateSetupGroup(p guidedProfile, kind string, files map[string]string) error {
	key := "coordinator-public-key.hex"
	if p.Role == "coordinator" {
		key = "setup-coordinator.hex"
	}
	var expected []string
	switch kind {
	case "identity":
		expected = []string{filepath.Join(p.Keys, "identity.json")}
	case "definition":
		expected = []string{filepath.Join(p.Work, "ceremony/public/ceremony.json"), filepath.Join(p.Work, "ceremony/public/ceremony.sig"), filepath.Join(p.Trust, key)}
	case "storage":
		expected = []string{filepath.Join(p.Work, "ceremony/config/relay-storage.json")}
	case "initialization":
		if p.Role != "coordinator" || len(files) == 0 {
			return errors.New("invalid initialization binding")
		}
		for path := range files {
			if filepath.Clean(path) != path || !strings.HasPrefix(path, filepath.Join(p.Work, "coordinator-setup/frozen")+string(os.PathSeparator)) {
				return errors.New("initialization binding escaped frozen inputs")
			}
			expected = append(expected, path)
		}
	default:
		return errors.New("unknown setup binding group")
	}
	if len(files) != len(expected) {
		return errors.New("incomplete setup binding group")
	}
	for _, path := range expected {
		h := files[path]
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return errors.New("invalid setup binding path or digest")
		}
	}
	return nil
}

func checkActivePreparation(name, role, release, work, trust, keys string) error {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		return nil
	}
	return checkPreparationRelease(name, role, release, work, trust, keys)
}

func upgradeV2SetupContinuity(p guidedProfile) (map[string]string, []string, error) {
	out := map[string]string{}
	var absent []string
	key := "coordinator-public-key.hex"
	if p.Role == "coordinator" {
		key = "setup-coordinator.hex"
	}
	for _, path := range []string{filepath.Join(p.Keys, "identity.json"), filepath.Join(p.Trust, key), filepath.Join(p.Work, "ceremony/public/ceremony.json"), filepath.Join(p.Work, "ceremony/public/ceremony.sig")} {
		h, err := setupFileHash(path)
		if errors.Is(err, os.ErrNotExist) {
			absent = append(absent, path)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		out[path] = h
	}
	root := filepath.Join(p.Work, "coordinator-setup/frozen")
	if _, err := os.Lstat(root); err == nil {
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("symlink in frozen setup")
			}
			if entry.IsDir() {
				return nil
			}
			h, err := setupFileHash(path)
			if err != nil {
				return err
			}
			out[path] = h
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return out, absent, nil
}

func upgradeV2SetupManifest(raw, images []byte, commit, platform, proof string) error {
	var m setupReleaseManifestV3
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Schema != "ceremony-software-manifest-v3" || m.CLICommit != commit || m.ReleaseTag != "role-images-"+commit {
		return errors.New("original setup software manifest mismatch")
	}
	// The software manifest embeds the same map with its own JSON key order.
	// Both documents are attested; compare parsed contents, rejecting duplicates.
	var a, b any
	if rejectCommitJournalDuplicateFields(m.RoleImages) != nil || rejectCommitJournalDuplicateFields(images) != nil || json.Unmarshal(m.RoleImages, &a) != nil || json.Unmarshal(images, &b) != nil || !reflect.DeepEqual(a, b) {
		return errors.New("original setup image map mismatch")
	}
	asset, _, _, err := pinnedProofAssetFrom(m.Inputs, strings.TrimPrefix(platform, "linux/"))
	if err != nil {
		return err
	}
	if "sha256:"+asset.SHA256 != proof {
		return errors.New("original setup proof-tool differs from measured image")
	}
	return nil
}

func prepareWorkspaceProofAsset(work, arch string) (setupBinary, error) {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return setupBinary{}, err
	}
	if len(history) == 0 || history[0].Setup == nil {
		return prepareProofAsset(filepath.Join(work, "approved-tools"), arch)
	}
	s := history[0]
	if _, _, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true); err != nil {
		return setupBinary{}, err
	}
	var m setupReleaseManifestV3
	if err := json.Unmarshal(s.Setup.Manifest, &m); err != nil {
		return setupBinary{}, err
	}
	a, commit, name, err := pinnedProofAssetFrom(m.Inputs, arch)
	return prepareProofAssetPinned(filepath.Join(work, "approved-tools"), a, commit, name, arch, err)
}

func upgradeV2PrepareSetupState(s upgradeSelectionV2, first bool) error {
	if first {
		state := upgradeSetupStateV2{Schema: "relay-upgrade-setup-bindings/v1", Owner: s.Profile, Groups: map[string]map[string]string{}}
		if err := setupWriteNewOrExact(upgradeV2SetupStatePath(s.Profile.Work), state); err != nil {
			return err
		}
	}
	// Explicit protected parent linkage lets keygen retain its original image
	// although its /work mount is the parent's keys directory.
	owner := s.Profile
	owner.Credentials, owner.R2Parent, owner.R2Control = "", "", ""
	return setupWriteNewOrExact(filepath.Join(s.Profile.Keys, ".relay-upgrade-owner.json"), owner)
}

func preparationSettingsRoot(work, requested string) (string, error) {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return "", err
	}
	if len(history) > 0 {
		if requested != "" && requested != history[0].SettingsRoot {
			return "", errors.New("settings root differs from active update")
		}
		return history[0].SettingsRoot, nil
	}
	if requested != "" {
		if err := validateCommitLocalPath(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	return guidedRoot()
}

func upgradeV2CaptureSetup(work, kind string) (map[string]string, error) {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 || history[0].Setup == nil {
		return nil, nil
	}
	s := history[0]
	if err := upgradeV2CheckDraft(s); err != nil {
		return nil, err
	}
	p := s.Profile
	switch kind {
	case "identity":
		return upgradeV2CaptureFiles(filepath.Join(p.Keys, "identity.json"))
	case "definition":
		key := "coordinator-public-key.hex"
		if p.Role == "coordinator" {
			key = "setup-coordinator.hex"
		}
		return upgradeV2CaptureFiles(filepath.Join(work, "ceremony/public/ceremony.json"), filepath.Join(work, "ceremony/public/ceremony.sig"), filepath.Join(p.Trust, key))
	case "storage":
		return upgradeV2CaptureFiles(filepath.Join(work, "ceremony/config/relay-storage.json"))
	case "initialization":
		files, _, err := upgradeV2SetupContinuity(p)
		for path := range files {
			if !strings.HasPrefix(path, filepath.Join(work, "coordinator-setup/frozen")+string(os.PathSeparator)) {
				delete(files, path)
			}
		}
		return files, err
	}
	return nil, errors.New("unknown setup verification group")
}

func upgradeV2RetainSetup(work, kind string) error {
	files, err := upgradeV2CaptureSetup(work, kind)
	if err != nil {
		return err
	}
	if files == nil {
		return nil
	}
	return upgradeV2RecordSetupGroup(work, kind, files)
}

// Setup groups describe canonical inputs. Do not verify an alternate file and
// then accidentally retain the hash of the canonical, unused file.
func upgradeV2CheckSetupInputPaths(p guidedProfile, storage, key string) error {
	history, _, err := upgradeV2ReadHistory(p.Work)
	if err != nil || len(history) == 0 || history[0].Setup == nil {
		return err
	}
	keyName := "coordinator-public-key.hex"
	if p.Role == "coordinator" {
		keyName = "setup-coordinator.hex"
	}
	if storage != filepath.Join(p.Work, "ceremony/config/relay-storage.json") || key != filepath.Join(p.Trust, keyName) {
		return errors.New("upgraded setup requires its exact retained storage and coordinator-key paths")
	}
	return nil
}

func upgradeV2SelectionWork(p guidedProfile) (string, error) {
	if p.Role != "keygen" {
		return p.Work, nil
	}
	var owner guidedProfile
	if err := setupReadJSON(filepath.Join(p.Work, ".relay-upgrade-owner.json"), &owner); errors.Is(err, os.ErrNotExist) {
		return p.Work, nil
	} else if err != nil {
		return "", err
	}
	if owner.Keys != p.Work || owner.ReleaseCommit != p.ReleaseCommit || owner.Work == p.Work {
		return "", errors.New("key generation parent does not match this installation")
	}
	return owner.Work, nil
}
