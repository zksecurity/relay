package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/upgrade"
)

func TestUpgradeDraftRejectsUnprotectedDraft(t *testing.T) {
	for _, role := range []string{"coordinator", "participant"} {
		t.Run(role, func(t *testing.T) {
			s, _ := testDraftUpgrade(t, role)
			if err := os.Chmod(s.Setup.Draft, 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := upgradeV2DraftProfile(s.Profile.Work, s.Profile.Name, role); err == nil {
				t.Fatal("accepted a world-readable draft")
			}
		})
	}
}

func TestUpgradeDraftUsesExactVerifiedPaths(t *testing.T) {
	s, _ := testDraftUpgrade(t, "participant")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	storage := filepath.Join(s.Profile.Work, "ceremony/config/relay-storage.json")
	key := filepath.Join(s.Profile.Trust, "coordinator-public-key.hex")
	if err := upgradeV2CheckSetupInputPaths(s.Profile, storage, key); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][2]string{{storage + ".other", key}, {storage, key + ".other"}} {
		if err := upgradeV2CheckSetupInputPaths(s.Profile, paths[0], paths[1]); err == nil {
			t.Fatal("accepted a different input from the retained group")
		}
	}
}

func TestUpgradeDraftRejectsMalformedBindingGroups(t *testing.T) {
	s, _ := testDraftUpgrade(t, "coordinator")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind  string
		files map[string]string
	}{
		{"unknown", map[string]string{}},
		{"identity", map[string]string{}},
		{"definition", map[string]string{filepath.Join(s.Profile.Work, "ceremony/public/ceremony.json"): strings.Repeat("a", 64)}},
		{"initialization", map[string]string{filepath.Join(s.Profile.Work, "outside.json"): strings.Repeat("a", 64)}},
	} {
		if err := upgradeV2RecordSetupGroup(s.Profile.Work, tc.kind, tc.files); err == nil {
			t.Fatalf("accepted malformed %s group", tc.kind)
		}
	}
}

func TestUpgradeDraftSecondCommandRejectsChangedSharedProfile(t *testing.T) {
	for _, field := range []string{"image", "platform", "config"} {
		t.Run(field, func(t *testing.T) {
			s, d := testDraftUpgrade(t, "participant")
			if err := upgradeV2Activate(s, ""); err != nil {
				t.Fatal(err)
			}
			old := releaseCommit
			releaseCommit = d.TargetApp
			t.Cleanup(func() { releaseCommit = old })
			p := s.Profile
			switch field {
			case "image":
				p.Image = "sha256:" + strings.Repeat("f", 64)
			case "platform":
				p.Platform = "linux/amd64"
				if p.Platform == s.Profile.Platform {
					p.Platform = "linux/arm64"
				}
			case "config":
				p.Config = filepath.Join(p.Work, "different.json")
			}
			dir, err := guidedDirectory(s.SettingsRoot, p.Name, p.Role)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := saveJSONAtomic(filepath.Join(dir, "profile.json"), p); err != nil {
				t.Fatal(err)
			}
			err = runCeremonyUpgradeV2([]string{p.Name, "--role", p.Role, "--release", "role-images-" + d.TargetApp, "--settings-root", s.SettingsRoot})
			if err == nil || !strings.Contains(err.Error(), "prepared profile changed installation") {
				t.Fatalf("changed %s was not rejected at descriptor check: %v", field, err)
			}
		})
	}
}

func testDraftUpgrade(t *testing.T, role string) (upgradeSelectionV2, upgrade.DeclarationV2) {
	t.Helper()
	s, d := testUpgradeV2(t, role)
	s.Profile.Platform = "linux/" + runtime.GOARCH
	d.Platform = s.Profile.Platform
	p := s.Profile
	var path string
	if role == "coordinator" {
		path = filepath.Join(p.Work, "coordinator-setup/draft.json")
		os.MkdirAll(filepath.Dir(path), 0700)
		v := coordinatorDraft{Schema: "relay-coordinator-draft-v1", Name: p.Name, Release: "role-images-" + p.ReleaseCommit, Work: p.Work, Trust: p.Trust, Keys: p.Keys, Status: "draft", Storage: map[string]string{}}
		if err := saveJSONAtomic(path, v); err != nil {
			t.Fatal(err)
		}
	} else {
		path = filepath.Join(p.Work, "role-preparation/draft.json")
		os.MkdirAll(filepath.Dir(path), 0700)
		v := rolePreparation{Schema: "relay-role-preparation-v1", Name: p.Name, Role: role, Release: "role-images-" + p.ReleaseCommit, Work: p.Work, Trust: p.Trust, Keys: p.Keys, Values: map[string]string{}}
		if err := saveJSONAtomic(path, v); err != nil {
			t.Fatal(err)
		}
		if role == "participant" {
			s.Profile.Config = filepath.Join(p.Work, "ceremony/config/participant-phase1.json")
		}
	}
	inputs, _ := json.Marshal(map[string]any{"schema": "relay-role-image-inputs/v1", "mpc": map[string]any{
		"linux_amd64": proofReleaseAsset{URL: "https://github.com/zksecurity/proof-tool/releases/download/mpc-ci-" + strings.Repeat("a", 40) + "/mpc-ceremony", SHA256: strings.TrimPrefix(d.ProofToolSHA256, "sha256:")},
		"linux_arm64": proofReleaseAsset{URL: "https://github.com/zksecurity/proof-tool/releases/download/mpc-ci-" + strings.Repeat("a", 40) + "/mpc-ceremony-linux-arm64", SHA256: strings.TrimPrefix(d.ProofToolSHA256, "sha256:")},
	}})
	manifest, _ := json.Marshal(setupReleaseManifestV3{Schema: "ceremony-software-manifest-v3", ReleaseTag: "role-images-" + d.OriginalRelease, CLICommit: d.OriginalRelease, RoleImages: s.OriginalMap, Inputs: inputs})
	s.Setup = &upgradeSetupV2{Draft: path, Manifest: manifest}
	var err error
	s.Bindings, s.Setup.Absent, err = upgradeV2SetupContinuity(s.Profile)
	if err != nil {
		t.Fatal(err)
	}
	testUpgradeV2Report(t, &s, &d)
	return s, d
}

func TestUpgradeDraftWithoutIdentityOrSharedProfile(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "auditor", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			s, d := testDraftUpgrade(t, role)
			old := releaseCommit
			releaseCommit = d.TargetApp
			t.Cleanup(func() { releaseCommit = old })
			if err := upgradeV2Activate(s, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true); err != nil {
				t.Fatal(err)
			}
			for _, path := range s.Setup.Absent {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("activation created ceremony/identity output")
				}
			}
			// A later real setup action can commit an exact new artifact. It cannot
			// replace that artifact, and losing the history must not reset setup.
			identity := filepath.Join(s.Profile.Keys, "identity.json")
			if err := os.WriteFile(identity, []byte("test continuity, not an authenticated identity"), 0600); err != nil {
				t.Fatal(err)
			}
			files, err := upgradeV2CaptureSetup(s.Profile.Work, "identity")
			if err != nil {
				t.Fatal(err)
			}
			if err := upgradeV2RecordSetupGroup(s.Profile.Work, "identity", files); err != nil {
				t.Fatal(err)
			}
			if err := upgradeV2RecordSetupGroup(s.Profile.Work, "identity", files); err != nil {
				t.Fatal("idempotent commitment", err)
			}
			if err := os.WriteFile(identity, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true); err == nil {
				t.Fatal("changed committed identity accepted")
			}
		})
	}
}

func TestUpgradeDraftBindingsCannotDisappear(t *testing.T) {
	s, _ := testDraftUpgrade(t, "coordinator")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(upgradeV2SetupStatePath(s.Profile.Work)); err != nil {
		t.Fatal(err)
	}
	if err := upgradeV2CheckDraft(s); err == nil {
		t.Fatal("lost setup binding history treated as an empty draft")
	}
}

func TestUpgradeDraftFrozenInputsAndSecondUpdate(t *testing.T) {
	s, d := testDraftUpgrade(t, "participant")
	old := releaseCommit
	releaseCommit = d.TargetApp
	t.Cleanup(func() { releaseCommit = old })
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	_, previous, err := upgradeV2ReadHistory(s.Profile.Work)
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary shared-profile creation uses exactly the descriptor's config.
	if !upgradeV2ProfileMatches(s.Profile, s.Profile, d) {
		t.Fatal("prepared profile rejected")
	}
	wrong := s.Profile
	wrong.Config = filepath.Join(s.Profile.Work, "different.json")
	if upgradeV2ProfileMatches(wrong, s.Profile, d) {
		t.Fatal("different config accepted")
	}
	next := s
	next.Previous = previous
	d.SourceApp = d.TargetApp
	d.TargetApp = strings.Repeat("f", 40)
	d.SafePredecessors = append(d.SafePredecessors, d.SourceApp)
	next.TargetMap = upgradeTestReleaseMap(d.TargetApp, strings.Repeat("d", 64))
	testUpgradeV2Report(t, &next, &d)
	if err := upgradeV2Activate(next, previous); err != nil {
		t.Fatal("second draft update", err)
	}
}

func TestUpgradeDraftKeygenParentAndSettingsRoot(t *testing.T) {
	s, d := testDraftUpgrade(t, "coordinator")
	old := releaseCommit
	releaseCommit = d.TargetApp
	t.Cleanup(func() { releaseCommit = old })
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	child := guidedProfile{Role: "keygen", Image: d.SigningImage, Platform: d.Platform, Work: s.Profile.Keys, ReleaseCommit: d.OriginalRelease}
	if _, _, _, err := upgradeV2Selected(child, s.SettingsRoot, true); err != nil {
		t.Fatal(err)
	}
	child.ReleaseCommit = d.TargetApp
	if _, err := upgradeV2SelectionWork(child); err == nil {
		t.Fatal("wrong parent accepted")
	}
	root, err := preparationSettingsRoot(s.Profile.Work, "")
	if err != nil || root != s.SettingsRoot {
		t.Fatal("setup lost nondefault settings root", err)
	}
	if _, err := preparationSettingsRoot(s.Profile.Work, filepath.Join(t.TempDir(), "other")); err == nil {
		t.Fatal("different settings root accepted")
	}
}

func TestUpgradeDraftRetainsPartialInitialization(t *testing.T) {
	s, d := testDraftUpgrade(t, "coordinator")
	path := filepath.Join(s.Profile.Work, "coordinator-setup/frozen/policy.json")
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte("frozen policy fixture"), 0600)
	s.Bindings, s.Setup.Absent, _ = upgradeV2SetupContinuity(s.Profile)
	old := releaseCommit
	releaseCommit = d.TargetApp
	t.Cleanup(func() { releaseCommit = old })
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("changed"), 0600)
	if _, _, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true); err == nil {
		t.Fatal("changed frozen initialization accepted")
	}
}
