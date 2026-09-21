package main

import (
	"bytes"
	"encoding/json"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/upgrade"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testUpgradeV2(t *testing.T, role string) (upgradeSelectionV2, upgrade.DeclarationV2) {
	t.Helper()
	root := t.TempDir()
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	p := guidedProfile{Schema: guidedSchema, Name: "test", Role: role, ReleaseCommit: a, Platform: "linux/arm64", Work: filepath.Join(root, "work"), Trust: filepath.Join(root, "trust"), Keys: filepath.Join(root, "keys")}
	for _, dir := range []string{p.Work, p.Trust, p.Keys} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	original := upgradeTestReleaseMap(a, strings.Repeat("c", 64))
	p.Image, _ = selectReleaseImage(original, a, role, p.Platform)
	signing, _ := selectReleaseImage(original, a, "decision-signer", p.Platform)
	d := upgrade.DeclarationV2{Schema: upgrade.SchemaV2, OriginalRelease: a, SourceApp: a, TargetApp: b, Role: role, Host: runtime.GOOS + "/" + runtime.GOARCH, Platform: p.Platform, OriginalImage: p.Image, SigningImage: signing, ProofToolSHA256: "sha256:" + strings.Repeat("e", 64), Protocol: "proof-tool-mpc-ceremony-definition-v4", StorageLayout: "storage-first-v2", ProfileSchema: guidedSchema, JournalSchema: workflowV4JournalSchema, SafePredecessors: []string{a}}
	target := upgradeTestReleaseMap(b, strings.Repeat("d", 64))
	if role != "participant" && role != "release-signer" {
		d.OnlineImage, _ = selectReleaseImage(target, b, role, p.Platform)
	}
	seen := map[string]bool{}
	for _, kind := range upgradeV2RoleKinds(role) {
		adapter, err := upgrade.Adapter(kind)
		if err != nil {
			t.Fatal(err)
		}
		if !seen[adapter] {
			d.Adapters = append(d.Adapters, adapter)
			seen[adapter] = true
		}
	}
	exe, _ := os.Executable()
	hash, err := setupFileHash(exe)
	if err != nil {
		t.Fatal(err)
	}
	s := upgradeSelectionV2{Schema: upgradeSelectionV2Schema, Profile: p, OriginalMap: original, TargetMap: target, SettingsRoot: root, Launcher: exe, LauncherSHA256: hash, StartPath: filepath.Join(root, "start.sh"), PreviousStart: []byte("original\n"), Kinds: upgradeV2RoleKinds(role), Bindings: map[string]string{}}
	file := filepath.Join(p.Work, "environment.json")
	if err := os.WriteFile(file, []byte("frozen"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Bindings[file], _ = setupFileHash(file)
	if err := os.WriteFile(s.StartPath, s.PreviousStart, 0700); err != nil {
		t.Fatal(err)
	}
	testUpgradeV2Report(t, &s, &d)
	return s, d
}

func TestUpgradeV2PreservesInterruptedContributionAndHighWater(t *testing.T) {
	s, d := testUpgradeV2(t, "participant")
	protocol, b := workflowV4TestBinding(t)
	b.Work = s.Profile.Work
	for name, r := range b.Runtimes {
		r.Image = s.Profile.Image
		if name == "signer" {
			r.Image = d.SigningImage
		}
		r.Mounts = map[string]string{"/work": b.Work, "/trust": s.Profile.Trust, "/keys": s.Profile.Keys}
		b.Runtimes[name] = r
	}
	j, err := openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	plan := workflowV4TestPlan(t, b)
	plan.Runtime = b.Runtimes["contributor"]
	if err := j.prepare(plan); err != nil {
		t.Fatal(err)
	}
	if err := j.transition(plan.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenWorkspaceHighWater(b.Work, b.CeremonyID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(b.Work, "workflow-v4", "state.json")
	before, _ := os.ReadFile(path)
	inv, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Pending) != 1 {
		t.Fatalf("interrupted contribution omitted: %+v", inv)
	}
	s.Kinds, s.InventorySHA256 = inv.Kinds, inv.digest()
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("activation rewrote pending operation")
	}
	j, err = openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal("original journal no longer opens", err)
	}
	defer j.close()
	called := false
	if err := j.runPrepared(plan.ID, func(workflowV4OperationPlan) error { called = true; return nil }); err == nil || called {
		t.Fatal("interrupted computation was replayed")
	}
}

func TestUpgradeV2ProducerRequiresExactQualification(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	binary, err := os.ReadFile(s.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	files, err := generateUpgradeV2(d, d.TargetApp, s.OriginalMap, s.TargetMap, s.Qualification, binary)
	if err != nil || len(files) != 2 {
		t.Fatal(err)
	}
	if _, err := generateUpgradeV2(d, d.TargetApp, s.OriginalMap, s.TargetMap, s.Qualification, []byte("different candidate")); err == nil {
		t.Fatal("different build promoted")
	}
	if _, err := generateUpgradeV2(d, d.TargetApp, s.OriginalMap, s.TargetMap, []byte(`{}`), binary); err == nil {
		t.Fatal("missing test evidence promoted")
	}
}
func testUpgradeV2Report(t *testing.T, s *upgradeSelectionV2, d *upgrade.DeclarationV2) {
	t.Helper()
	q := upgrade.QualificationV2{Schema: "relay-upgrade-qualification/v2", OriginalRelease: d.OriginalRelease, SourceApp: d.SourceApp, TargetApp: d.TargetApp, Role: d.Role, Host: d.Host, Platform: d.Platform, OnlineImage: d.OnlineImage, ProofToolSHA256: d.ProofToolSHA256, LauncherSHA256: "sha256:" + s.LauncherSHA256, Passed: append([]string{}, upgrade.QualificationChecks...)}
	q.OriginalImage, q.SigningImage = d.OriginalImage, d.SigningImage
	q.Predecessors = map[string]string{}
	for _, commit := range d.SafePredecessors {
		q.Predecessors[commit] = "sha256:" + s.LauncherSHA256
	}
	s.Qualification, _ = json.Marshal(q)
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(s.Qualification)
	s.Declaration, _ = json.Marshal(d)
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeV2RoleAndChildBindings(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	if !upgradeV2ProfileMatches(s.Profile, s.Profile, d) {
		t.Fatal("valid profile refused")
	}
	bad := d
	bad.Role = "auditor"
	if upgradeV2ProfileMatches(s.Profile, s.Profile, bad) {
		t.Fatal("auditor authority accepted for coordinator")
	}
	bad = d
	bad.Platform = "linux/amd64"
	if upgradeV2ProfileMatches(s.Profile, s.Profile, bad) {
		t.Fatal("wrong architecture accepted")
	}
	child := s.Profile
	child.Role = "decision-signer"
	child.Image = d.SigningImage
	child.Name = "offline-test"
	if !upgradeV2ProfileMatches(child, s.Profile, d) {
		t.Fatal("pinned signer refused")
	}
	child.Image = d.OnlineImage
	if upgradeV2ProfileMatches(child, s.Profile, d) {
		t.Fatal("online image used for signing")
	}
}

func TestUpgradeV2AtomicMultiHopAndCredentialRenewal(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	history, hash, err := upgradeV2ReadHistory(s.Profile.Work)
	if err != nil || len(history) != 1 {
		t.Fatal(err)
	}
	if err := upgradeV2Activate(s, ""); err == nil {
		t.Fatal("stale activation succeeded")
	}
	next := s
	next.Previous = hash
	next.Profile.Credentials = "/protected/renewed-reference"
	d.SourceApp = d.TargetApp
	d.TargetApp = strings.Repeat("f", 40)
	d.SafePredecessors = append(d.SafePredecessors, d.SourceApp)
	next.TargetMap = upgradeTestReleaseMap(d.TargetApp, strings.Repeat("d", 64))
	testUpgradeV2Report(t, &next, &d)
	if err := upgradeV2Activate(next, hash); err != nil {
		t.Fatal(err)
	}
	history, _, err = upgradeV2ReadHistory(s.Profile.Work)
	if err != nil || len(history) != 2 {
		t.Fatal("credential reference broke history", err)
	}
	if err := os.WriteFile(filepath.Join(upgradeV2Root(s.Profile.Work), "generations", hash+".json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := upgradeV2ReadHistory(s.Profile.Work); err == nil {
		t.Fatal("changed generation accepted")
	}
}

func TestUpgradeV2SelectedRolesAndFrozenInputMutation(t *testing.T) {
	old := releaseCommit
	t.Cleanup(func() { releaseCommit = old })
	for _, role := range []string{"coordinator", "participant", "auditor", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			s, d := testUpgradeV2(t, role)
			releaseCommit = d.TargetApp
			if err := upgradeV2Activate(s, ""); err != nil {
				t.Fatal(err)
			}
			got, found, err := upgradeV2Resolve(s.Profile, s.SettingsRoot)
			if err != nil || !found {
				t.Fatal(err)
			}
			if got.Image != s.Profile.Image || got.UpgradeOnlineImage != d.OnlineImage {
				t.Fatal("wrong runtime selection")
			}
			for path := range s.Bindings {
				if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				break
			}
			if _, _, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true); err == nil {
				t.Fatal("changed frozen input accepted")
			}
		})
	}
}

func TestUpgradeV2InventoryDetectsChangesAndUnknownState(t *testing.T) {
	s, d := testUpgradeV2(t, "participant")
	before, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Profile.Work, "environment.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	if before.digest() == after.digest() {
		t.Fatal("changed inventory not detected")
	}
	if err := os.Mkdir(filepath.Join(s.Profile.Work, "unknown-workflow"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("unknown retained state accepted")
	}
}

func TestUpgradeV2OfflineRootCannotComeFromBundle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "root.json")
	os.WriteFile(path, []byte("untrusted"), 0600)
	if _, _, err := newUpgradeAssets(root, path); err == nil {
		t.Fatal("transferred root became authority")
	}
	if _, _, err := newUpgradeAssets(root, ""); err == nil {
		t.Fatal("missing independent trust root accepted")
	}
}

func TestUpgradeV2OfflineAssetsRequireLocalProvenance(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	commit := strings.Repeat("a", 40)
	if err := os.MkdirAll(filepath.Join(bundle, commit), 0700); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(root, "independent-roots.json")
	os.WriteFile(trust, []byte("test root"), 0600)
	asset := "relay-role-images.release.json"
	os.WriteFile(filepath.Join(bundle, commit, asset), []byte("public artifact"), 0600)
	a, cleanup, err := newUpgradeAssets(bundle, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := a.get(commit, asset); err == nil {
		t.Fatal("missing offline provenance accepted")
	}
	os.WriteFile(filepath.Join(bundle, commit, asset+".sigstore.jsonl"), []byte("test provenance"), 0600)
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0700)
	script := `#!/bin/sh
test "$1" = attestation && test "$2" = verify || exit 91
case "$*" in *--bundle*--custom-trusted-root*--source-ref*--source-digest*--deny-self-hosted-runners*) ;; *) exit 92;; esac
exit 0
`
	os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0700)
	t.Setenv("PATH", bin)
	if raw, err := a.get(commit, asset); err != nil || string(raw) != "public artifact" {
		t.Fatal("offline verification route", err)
	}
	os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\nexit 23\n"), 0700)
	if _, err := a.get(commit, asset); err == nil {
		t.Fatal("failed provenance verification accepted")
	}
}

func TestUpgradeV2ChangedBindingDoesNotPublish(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	_, previous, _ := upgradeV2ReadHistory(s.Profile.Work)
	next := s
	next.Previous = previous
	next.Bindings = map[string]string{"replacement": strings.Repeat("e", 64)}
	d.SourceApp = d.TargetApp
	d.TargetApp = strings.Repeat("f", 40)
	d.SafePredecessors = append(d.SafePredecessors, d.SourceApp)
	testUpgradeV2Report(t, &next, &d)
	if err := upgradeV2Activate(next, previous); err == nil {
		t.Fatal("changed binding selected")
	}
	_, got, err := upgradeV2ReadHistory(s.Profile.Work)
	if err != nil || got != previous {
		t.Fatal("failed update corrupted selected history", err)
	}
}

func TestUpgradeV2ProofApprovalIndependentOfDeclaration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ceremony.json")
	hash := "sha256:" + strings.Repeat("a", 64)
	raw := []byte(`{"schema":"proof-tool-mpc-ceremony-definition-v4","software":{"binaries":[{"goos":"linux","goarch":"arm64","tool_binary":{"sha256":"` + hash + `"}}]}}`)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := upgradeV2CheckApprovedProof(file, "linux/arm64", hash); err != nil {
		t.Fatal(err)
	}
	if upgradeV2CheckApprovedProof(file, "linux/arm64", "sha256:"+strings.Repeat("b", 64)) == nil {
		t.Fatal("declaration overrode signed software policy")
	}
}

func TestUpgradeV2NewActionsPinImageButRetainedActionsDoNotChange(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	p := s.Profile
	p.UpgradeOnlineImage = d.OnlineImage
	dir := t.TempDir()
	command := []string{"relay", "coordinator", "publish", "--verify"}
	if _, _, err := prepareGuidedAction(dir, "old", command); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareGuidedAction(dir, "fresh", command, p); err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]string{"old": p.Image, "fresh": d.OnlineImage} {
		got, err := upgradeV2SavedActionImage(p, filepath.Join(dir, "actions", action, "profile.json"), action)
		if err != nil || got != want {
			t.Fatal(action, got, err)
		}
	}
	if got := upgradeV2NewActionImage(p, []string{"mpc-ceremony", "ops", "sign"}); got != p.Image {
		t.Fatal("proof action changed image")
	}
	if _, _, err := prepareGuidedAction(dir, "fresh", command, p); err != nil {
		t.Fatal("resume changed named action", err)
	}
}

func TestUpgradeV2DetectsUnknownNestedState(t *testing.T) {
	s, d := testUpgradeV2(t, "participant")
	if err := os.MkdirAll(filepath.Join(s.Profile.Work, "workflow-v4", "future-format"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("unknown nested workflow accepted")
	}
}

func TestUpgradeV2GeneratedScriptRecognition(t *testing.T) {
	s, _ := testUpgradeV2(t, "participant")
	s.SettingsRoot, _ = guidedRoot()
	p := s.Profile
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	lines := []string{"#!/usr/bin/env bash", "set -euo pipefail", "relay_launcher='/original/relay'", "ceremony_name=" + quote(p.Name), "ceremony_role=" + quote(p.Role), "ceremony_release=" + quote("role-images-"+p.ReleaseCommit), "ceremony_work=" + quote(p.Work), "ceremony_trust=" + quote(p.Trust), "ceremony_keys=" + quote(p.Keys), `if [[ "$ceremony_role" == coordinator ]]; then`, `  exec "$relay_launcher" coordinator prepare --name "$ceremony_name" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, `fi`, `exec "$relay_launcher" ceremony prepare --name "$ceremony_name" --role "$ceremony_role" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, ""}
	raw := []byte(strings.Join(lines, "\n"))
	if !upgradeV2GeneratedStart(raw, p) {
		t.Fatal("installer script not recognized")
	}
	if upgradeV2GeneratedStart(append(raw, []byte("echo operator-customization\n")...), p) {
		t.Fatal("custom script recognized")
	}
	custom := strings.Replace(string(raw), "relay_launcher='/original/relay'", "relay_launcher='/original/relay'; echo 'custom'", 1)
	if upgradeV2GeneratedStart([]byte(custom), p) {
		t.Fatal("operator commands classified as generated launcher assignment")
	}
	s.PreviousStart = raw
	os.WriteFile(s.StartPath, raw, 0700)
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	other := s
	other.SettingsRoot = filepath.Join(t.TempDir(), "other-settings")
	if err := upgradeV2WriteStart(other); err == nil {
		t.Fatal("rewrote custom-root entry point using default-root preparation")
	}
	for n := 0; n < 2; n++ {
		if err := upgradeV2WriteStart(s); err != nil {
			t.Fatal(err)
		}
	}
	updated, err := os.ReadFile(s.StartPath)
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = "relay_launcher=" + quote(s.Launcher)
	if string(updated) != strings.Join(lines, "\n") {
		t.Fatal("upgrade changed setup entry point or frozen ceremony settings")
	}
}
