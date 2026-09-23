package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/upgrade"
)

func TestUpgradePublicationIsCreateOnlyAndRestartable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selection.json")
	want := []byte(`{"complete":true}`)
	for i := 0; i < 2; i++ {
		if err := publishPublicInput(path, want); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishPublicInput(path, []byte(`{"other":true}`)); err == nil {
		t.Fatal("replaced selection")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatal("selection changed", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unprotected selection")
	}
	// An abandoned staging file is never interpreted as activated software.
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".public-import-interrupted"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishPublicInput(path, want); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeStartRecoveryPreservesEdits(t *testing.T) {
	root := t.TempDir()
	p := guidedProfile{Name: "ceremony-'quoted", Work: filepath.Join(root, "work")}
	s := ceremonyUpgradeSelection{StartPath: filepath.Join(root, "start.sh"), PreviousStart: []byte("old launcher\n"), Launcher: "/path with space/relay", SettingsRoot: "/settings's path"}
	if err := os.WriteFile(s.StartPath, s.PreviousStart, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := upgradeInstallStart(s, p); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(s.StartPath)
	if string(got) != string(upgradeStartBytes(s, p)) {
		t.Fatal("wrong script")
	}
	info, _ := os.Stat(s.StartPath)
	if info.Mode().Perm() != 0700 {
		t.Fatal("script not private and executable")
	}
	if err := os.WriteFile(s.StartPath, []byte("operator change"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := upgradeInstallStart(s, p); err == nil {
		t.Fatal("overwrote operator edit")
	}
}

func TestUpgradeContainerMountExclusion(t *testing.T) {
	p := guidedProfile{Work: "/role/work", Trust: "/role/trust", Keys: "/role/keys"}
	for _, source := range []string{"/", "/role/work", "/role/work/sub", "/role", "/role/keys", "/role/trust"} {
		raw, _ := json.Marshal([]any{map[string]any{"Mounts": []any{map[string]string{"Type": "bind", "Source": source}}}})
		if upgradeCheckMounts(raw, p) == nil {
			t.Fatal("accepted overlapping mount", source)
		}
	}
	for _, raw := range []string{`[]`, `[{}]`, `invalid`} {
		if upgradeCheckMounts([]byte(raw), p) == nil {
			t.Fatal("accepted invalid inspection")
		}
	}
	if err := upgradeCheckMounts([]byte(`[{"Mounts":[{"Type":"bind","Source":"/role/work-other"}]}]`), p); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRejectsUntrackedCoordinatorWork(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	j, err := openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	p := guidedProfile{Work: b.Work}
	if err := upgradeCheckJournal(p, b); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(b.Work, "workflow-v4", "coordinator")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "retained-intent.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upgradeCheckJournal(p, b); err == nil {
		t.Fatal("empty generic journal concealed coordinator work")
	}
}

func TestUpgradeRuntimeDispatch(t *testing.T) {
	previous := workflowV4ChildExecutor
	t.Cleanup(func() { workflowV4ChildExecutor = previous })
	var got []string
	workflowV4ChildExecutor = func(args []string) error { got = append([]string(nil), args...); return nil }
	p := guidedProfile{Role: "coordinator", Image: "original", UpgradeOnlineImage: "replacement", Work: t.TempDir(), Credentials: "/private/credentials"}
	if err := runWorkflowV4ProfileCommand(p, []string{"relay", "coordinator", "commit-v4"}, true); err != nil {
		t.Fatal(err)
	}
	if commandValue(got, "image") != "replacement" {
		t.Fatal("online image not replaced", got)
	}
	if err := runWorkflowV4ProfileCommand(p, []string{"mpc-ceremony", "inspect"}, false); err != nil {
		t.Fatal(err)
	}
	if commandValue(got, "image") != "original" || commandValue(got, "aws-credentials") != "" {
		t.Fatal("proof runtime or credentials changed", got)
	}
	if p.Image != "original" {
		t.Fatal("mutated pinned profile")
	}
	p.Role = "decision-signer"
	if runWorkflowV4ProfileCommand(p, []string{"relay"}, true) == nil {
		t.Fatal("allowed signer online upgrade")
	}
}

func TestUpgradeProfileHashExcludesOnlyRuntimeSelection(t *testing.T) {
	p := guidedProfile{Image: "source", ReleaseCommit: strings.Repeat("a", 40)}
	h := upgradeProfileHash(p)
	p.UpgradeOnlineImage = "target"
	if upgradeProfileHash(p) != h {
		t.Fatal("in-memory selection changed original binding")
	}
	p.Image = "changed"
	if upgradeProfileHash(p) == h {
		t.Fatal("image substitution not bound")
	}
}

func TestUpgradeEmptyReleasePolicyAuthorizesNothing(t *testing.T) {
	var p upgradeSourcePolicy
	if err := json.Unmarshal([]byte(`{"schema":"relay-upgrade-sources/v1","sources":[]}`), &p); err != nil {
		t.Fatal(err)
	}
	files, err := generateUpgradeDeclarations(p, strings.Repeat("a", 40), nil, []byte(`{"mpc":{}}`))
	if err != nil || len(files) != 0 {
		t.Fatal("unqualified upgrade published", err)
	}
}

func TestUpgradeManifestBindsProofAndReleasePair(t *testing.T) {
	source, target := strings.Repeat("a", 40), strings.Repeat("b", 40)
	hash := strings.Repeat("c", 64)
	image := "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + hash
	var policy upgradeSourcePolicy
	raw, _ := json.Marshal(map[string]any{"schema": "relay-upgrade-sources/v1", "sources": []any{map[string]any{"release": source, "platform": "linux/arm64", "online_image": image, "proof_tool_sha256": "sha256:" + hash, "old_version_reentry_safe": true}}})
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	var records []map[string]string
	for targetName, name := range map[string]string{"online": "relay-role-online", "offline": "relay-role-offline", "contributor": "relay-ceremony-tool"} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			records = append(records, map[string]string{"target": targetName, "platform": platform, "source_commit": target, "image": "ghcr.io/zksecurity/relay/" + name + "@sha256:" + hash})
		}
	}
	m, _ := json.Marshal(map[string]any{"schema": "relay-role-image-release/v1", "approval": "github-attested-ci", "source_commit": target, "launcher_commit": target, "images": records})
	pins := []byte(`{"mpc":{"linux_arm64":{"sha256":"` + hash + `"}}}`)
	files, err := generateUpgradeDeclarations(policy, target, m, pins)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatal("missing declaration")
	}
	for _, file := range files {
		d, err := upgrade.Decode(file)
		if err != nil || d.SourceRelease != source || d.TargetRelease != target {
			t.Fatal("wrong declaration", err)
		}
	}
	if _, err := generateUpgradeDeclarations(policy, target, m, []byte(`{"mpc":{}}`)); err == nil {
		t.Fatal("accepted missing proof pin")
	}
	policy.Sources = append(policy.Sources, policy.Sources[0])
	if _, err := generateUpgradeDeclarations(policy, target, m, pins); err == nil {
		t.Fatal("accepted duplicate source")
	}
}

func TestOperatorSelectedCleanExitDeclarationUsesOnlyFrozenRuntime(t *testing.T) {
	p := guidedProfile{
		Schema:        guidedSchema,
		Role:          "coordinator",
		ReleaseCommit: strings.Repeat("a", 40),
		Platform:      "linux/arm64",
		Image:         "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("b", 64),
	}
	d, err := upgradeOperatorSelectedCleanExitDeclaration(
		p,
		"ghcr.io/zksecurity/relay/relay-role-offline@sha256:"+strings.Repeat("c", 64),
		"ghcr.io/zksecurity/relay/relay-role-online@sha256:"+strings.Repeat("d", 64),
		"sha256:"+strings.Repeat("e", 64),
		strings.Repeat("f", 40),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !d.OperatorSelected() || d.QualificationSHA256 != "" || len(d.SafePredecessors) != 0 {
		t.Fatal("clean-exit admission claimed release-pair qualification")
	}
	if err := d.Cover(nil, upgradeV2RoleKinds("coordinator")); err != nil {
		t.Fatal("admission declaration omitted retained coordinator work", err)
	}
}

func upgradeTestReleaseMap(commit, digest string) []byte {
	var records []map[string]string
	for target, name := range map[string]string{"online": "relay-role-online", "offline": "relay-role-offline", "contributor": "relay-ceremony-tool"} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			records = append(records, map[string]string{"target": target, "platform": platform, "source_commit": commit, "image": "ghcr.io/zksecurity/relay/" + name + "@sha256:" + digest})
		}
	}
	raw, _ := json.Marshal(map[string]any{"schema": "relay-role-image-release/v1", "approval": "github-attested-ci", "source_commit": commit, "launcher_commit": commit, "images": records})
	return raw
}

func TestUpgradeSelectionRechecksFrozenBindings(t *testing.T) {
	originalCommit := releaseCommit
	releaseCommit = strings.Repeat("b", 40)
	t.Cleanup(func() { releaseCommit = originalCommit })
	root := t.TempDir()
	p := guidedProfile{Schema: guidedSchema, Name: "test", Role: "coordinator", Platform: "linux/arm64", ReleaseCommit: strings.Repeat("a", 40), Image: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("c", 64), Work: filepath.Join(root, "work"), Keys: filepath.Join(root, "keys"), Trust: filepath.Join(root, "trust")}
	signer := p
	signer.Name = offlineRoleAlias(p.Name, p.Role)
	signer.Role = "decision-signer"
	signer.Image = "ghcr.io/zksecurity/relay/relay-role-offline@sha256:" + strings.Repeat("c", 64)
	signerDir, err := guidedDirectory(root, signer.Name, signer.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(signerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(filepath.Join(signerDir, "profile.json"), signer, 0600); err != nil {
		t.Fatal(err)
	}
	d := upgrade.Declaration{Schema: upgrade.Schema, SourceRelease: p.ReleaseCommit, TargetRelease: releaseCommit, Role: p.Role, Platform: p.Platform, ProfileSchema: guidedSchema, WorkflowSchema: workflowV4JournalSchema, SourceOnlineImage: p.Image, TargetOnlineImage: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("d", 64), ProofToolSHA256: "sha256:" + strings.Repeat("e", 64), OldVersionReentrySafe: true}
	raw, _ := json.Marshal(d)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h, err := setupFileHash(exe)
	if err != nil {
		t.Fatal(err)
	}
	s := ceremonyUpgradeSelection{Schema: ceremonyUpgradeSchema, Declaration: d, ProfileSHA256: upgradeProfileHash(p), SignerSHA256: upgradeProfileHash(signer), Launcher: exe, LauncherSHA256: h, SettingsRoot: root, StartPath: filepath.Join(root, "start.sh"), SourceMap: upgradeTestReleaseMap(p.ReleaseCommit, strings.Repeat("c", 64)), TargetMap: upgradeTestReleaseMap(releaseCommit, strings.Repeat("d", 64)), DeclarationBytes: raw}
	for _, file := range []struct {
		name string
		hash *string
	}{{"ceremony/public/ceremony.json", &s.DefinitionSHA256}, {"ceremony/public/ceremony.sig", &s.SignatureSHA256}, {"ceremony/config/relay-storage.json", &s.StorageSHA256}} {
		path := filepath.Join(p.Work, file.name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(file.name), 0600); err != nil {
			t.Fatal(err)
		}
		*file.hash, err = setupFileHash(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := writeJSONNoReplace(upgradeSelectionPath(p), s, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpgradeSelection(p, root); err != nil {
		t.Fatal(err)
	}
	upgraded, err := applyCeremonyUpgrade(p, root)
	if err != nil || upgraded.UpgradeOnlineImage != d.TargetOnlineImage || upgraded.Image != p.Image {
		t.Fatal("upgrade selection failed", err)
	}
	changed := p
	changed.Credentials = "/different/reference"
	if _, err := readUpgradeSelection(changed, root); err == nil {
		t.Fatal("accepted changed profile")
	}
	if err := os.WriteFile(filepath.Join(p.Work, "ceremony/config/relay-storage.json"), []byte("changed target"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpgradeSelection(p, root); err == nil {
		t.Fatal("accepted substituted storage")
	}
	// An authorized upgrade never relaxes the global exact-release check.
	if checkLauncherRelease(p.ReleaseCommit) == nil {
		t.Fatal("global release check bypassed")
	}
}
