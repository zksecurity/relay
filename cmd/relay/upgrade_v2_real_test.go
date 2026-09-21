package main

// These tests execute real source/candidate binaries. Their local compatibility
// records are TEST-ONLY authorization for unpublished candidates; they do not
// verify delivered production attestations or enable a release pair.
import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/upgrade"
)

type upgradeRealFixture struct {
	request                    upgrade.QualificationRequest
	original, target, manifest []byte
}

func realUpgradeFixture(t *testing.T) upgradeRealFixture {
	t.Helper()
	path := os.Getenv("RELAY_UPGRADE_QUALIFICATION_REQUEST")
	if path == "" {
		t.Skip("set a private exact-asset upgrade request and candidate release map")
	}
	var f upgradeRealFixture
	if err := setupReadJSON(path, &f.request); err != nil {
		t.Fatal(err)
	}
	d := f.request.Declaration
	if d.Host != runtime.GOOS+"/"+runtime.GOARCH || d.Role != "coordinator" || d.SourceApp != d.OriginalRelease {
		t.Fatal("real journey fixture currently covers first coordinator update on this host")
	}
	for _, path := range []string{f.request.Candidate, f.request.Predecessors[d.SourceApp]} {
		if _, err := setupFileHash(path); err != nil {
			t.Fatal(err)
		}
	}
	assets, cleanup, err := newUpgradeAssets("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	f.original, err = assets.get(d.OriginalRelease, "relay-role-images.release.json")
	if err != nil {
		t.Fatal(err)
	}
	f.manifest, err = assets.get(d.OriginalRelease, "ceremony-software-manifest-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	native, err := assets.get(d.SourceApp, "relay-"+strings.ReplaceAll(d.Host, "/", "-"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := setupFileHash(f.request.Predecessors[d.SourceApp])
	if err != nil || hash != upgradeBytesHash(native) {
		t.Fatal("source executable differs from attested release")
	}
	f.target, err = readTesseraRegularFile(os.Getenv("RELAY_UPGRADE_TARGET_MAP"), 1<<20, false)
	if err != nil {
		t.Fatal("candidate image map required", err)
	}
	image, err := selectReleaseImage(f.original, d.OriginalRelease, d.Role, d.Platform)
	if err != nil || image != d.OriginalImage {
		t.Fatal("original image mismatch", err)
	}
	image, err = selectReleaseImage(f.target, d.TargetApp, d.Role, d.Platform)
	if err != nil || image != d.OnlineImage {
		t.Fatal("candidate image mismatch", err)
	}
	for _, image := range []string{d.OriginalImage, d.SigningImage, d.OnlineImage} {
		h, err := upgradeImageProofHashMode(image, d.Platform, false)
		if err != nil || h != d.ProofToolSHA256 {
			t.Fatal("real images must already be cached with unchanged proof-tool", err)
		}
	}
	return f
}

func realUpgradeSelection(t *testing.T, f upgradeRealFixture, p guidedProfile, root string, setup *upgradeSetupV2) upgradeSelectionV2 {
	t.Helper()
	d := f.request.Declaration
	p.ReleaseCommit, p.Image, p.Platform = d.OriginalRelease, d.OriginalImage, d.Platform
	hash, err := setupFileHash(f.request.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	s := upgradeSelectionV2{Schema: upgradeSelectionV2Schema, Profile: p, SettingsRoot: root, OriginalMap: f.original, TargetMap: f.target, Launcher: f.request.Candidate, LauncherSHA256: hash, StartPath: filepath.Join(filepath.Dir(p.Work), "start.sh"), Kinds: upgradeV2RoleKinds(p.Role), Setup: setup}
	if setup != nil {
		s.Setup.Manifest = f.manifest
		s.Bindings, s.Setup.Absent, err = upgradeV2SetupContinuity(p)
	} else {
		s.Bindings, err = upgradeV2BindingFiles(p)
	}
	if err != nil {
		t.Fatal(err)
	}
	// The fixture record never leaves the isolated temporary workspace.
	testUpgradeV2Report(t, &s, &d)
	var q upgrade.QualificationV2
	if err := json.Unmarshal(s.Qualification, &q); err != nil {
		t.Fatal(err)
	}
	for commit, binary := range f.request.Predecessors {
		h, err := setupFileHash(binary)
		if err != nil {
			t.Fatal(err)
		}
		q.Predecessors[commit] = "sha256:" + h
	}
	s.Qualification, _ = json.Marshal(q)
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(s.Qualification)
	s.Declaration, _ = json.Marshal(d)
	return s
}

func runRealUpgradeTerminal(t *testing.T, binary string, args []string, input string, deadline ...time.Duration) string {
	t.Helper()
	limit := 2 * time.Minute
	if len(deadline) > 0 {
		limit = deadline[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	// Wait for each prompt; piping all input into `script` can inject EOF before
	// the role's terminal reader is ready and is not a real user interaction.
	script := `set timeout $env(RELAY_UPGRADE_TEST_TIMEOUT)
set cmd [list $env(RELAY_UPGRADE_TEST_BINARY)]
for {set i 0} {$i < $env(RELAY_UPGRADE_TEST_ARGC)} {incr i} {
 lappend cmd $env(RELAY_UPGRADE_TEST_ARG_$i)
}
spawn -noecho {*}$cmd
set answers {}
if {$env(RELAY_UPGRADE_TEST_INPUT) ne ""} {set answers [split $env(RELAY_UPGRADE_TEST_INPUT) "\n"]}
foreach answer $answers {
 expect {
  -re {(\]: |: |\] )$} { send -- "$answer\r" }
  timeout {exit 90}
  eof {exit 91}
 }
}
expect {
 eof {}
 timeout {exit 92}
}
set result [wait]
exit [lindex $result 3]
`
	command := exec.CommandContext(ctx, "expect", "-c", script)
	command.Env = append(os.Environ(), "RELAY_UPGRADE_TEST_TIMEOUT="+strconv.Itoa(int(limit.Seconds())-5), "RELAY_UPGRADE_TEST_BINARY="+binary, "RELAY_UPGRADE_TEST_ARGC="+strconv.Itoa(len(args)), "RELAY_UPGRADE_TEST_INPUT="+strings.TrimSuffix(input, "\n"))
	for n, arg := range args {
		command.Env = append(command.Env, "RELAY_UPGRADE_TEST_ARG_"+strconv.Itoa(n)+"="+arg)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 2 * time.Second
	out, err := command.CombinedOutput()
	if err != nil {
		// Keep raw terminal output out of public test reports. A private opt-in
		// directory lets the operator inspect a failed local fixture.
		if root := os.Getenv("RELAY_UPGRADE_PRIVATE_LOG_DIR"); root != "" {
			if e := ensurePrivateDirectory(root); e != nil {
				t.Fatal(e)
			}
			file, e := os.CreateTemp(root, "terminal-*.log")
			if e != nil {
				t.Fatal(e)
			}
			_, _ = file.Write(out)
			_ = file.Close()
		}
		t.Fatalf("real CLI journey failed (%v); inspect the opt-in private terminal log", err)
	}
	return string(out)
}

func TestUpgradeRealDraftJourney(t *testing.T) {
	f := realUpgradeFixture(t)
	for _, role := range []string{"coordinator", "participant", "release-signer", "auditor"} {
		t.Run(role, func(t *testing.T) {
			local := f
			d := &local.request.Declaration
			d.Role = role
			var err error
			d.OriginalImage, err = selectReleaseImage(f.original, d.OriginalRelease, role, d.Platform)
			if err != nil {
				t.Fatal(err)
			}
			d.OnlineImage = ""
			if role == "coordinator" || role == "auditor" {
				d.OnlineImage, err = selectReleaseImage(f.target, d.TargetApp, role, d.Platform)
				if err != nil {
					t.Fatal(err)
				}
			}
			d.Adapters = nil
			seen := map[string]bool{}
			for _, kind := range upgradeV2RoleKinds(role) {
				a, err := upgrade.Adapter(kind)
				if err != nil {
					t.Fatal(err)
				}
				if !seen[a] {
					d.Adapters = append(d.Adapters, a)
					seen[a] = true
				}
			}
			runRealDraftUpgrade(t, local)
		})
	}
}

func runRealDraftUpgrade(t *testing.T, f upgradeRealFixture) {
	d := f.request.Declaration
	root := t.TempDir()
	work, trust, keys := filepath.Join(root, "work"), filepath.Join(root, "trust"), filepath.Join(root, "keys")
	for _, dir := range []string{work, trust, keys} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"coordinator", "prepare", "--name", "upgrade-draft-test", "--release", "role-images-" + d.OriginalRelease, "--work", work, "--trust", trust, "--keys", keys}
	if d.Role != "coordinator" {
		args[0] = "ceremony"
		args = append(args, "--role", d.Role)
	}
	// Actual released source creates the draft through its ordinary entrypoint.
	runRealUpgradeTerminal(t, f.request.Predecessors[d.SourceApp], args, "0\n")
	p, setup, err := upgradeV2DraftProfile(work, "upgrade-draft-test", d.Role)
	if err != nil {
		t.Fatal(err)
	}
	s := realUpgradeSelection(t, f, p, filepath.Join(root, "settings"), setup)
	p = s.Profile
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	lines := []string{"#!/usr/bin/env bash", "set -euo pipefail", "relay_launcher=" + quote(f.request.Predecessors[d.SourceApp]), "ceremony_name=" + quote(p.Name), "ceremony_role=" + quote(p.Role), "ceremony_release=" + quote("role-images-"+p.ReleaseCommit), "ceremony_work=" + quote(p.Work), "ceremony_trust=" + quote(p.Trust), "ceremony_keys=" + quote(p.Keys), `if [[ "$ceremony_role" == coordinator ]]; then`, `  exec "$relay_launcher" coordinator prepare --name "$ceremony_name" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, `fi`, `exec "$relay_launcher" ceremony prepare --name "$ceremony_name" --role "$ceremony_role" --release "$ceremony_release" --work "$ceremony_work" --trust "$ceremony_trust" --keys "$ceremony_keys"`, ""}
	s.PreviousStart = []byte(strings.Join(lines, "\n"))
	if err := os.WriteFile(s.StartPath, s.PreviousStart, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := setupFileHash(setup.Draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	if err := upgradeV2WriteStart(s); err != nil {
		t.Fatal(err)
	}
	out := runRealUpgradeTerminal(t, s.StartPath, nil, "0\n")
	expected := "NEXT REQUIRED ACTION"
	if d.Role != "coordinator" {
		expected = "NEXT SETUP STEP"
	}
	if strings.Contains(out, "error:") || !strings.Contains(out, expected) {
		t.Fatal("candidate did not resume the original draft")
	}
	after, _ := setupFileHash(setup.Draft)
	if before != after {
		t.Fatal("opening updated setup changed the draft")
	}
	for _, file := range setup.Absent {
		if _, err := os.Lstat(file); !os.IsNotExist(err) {
			t.Fatal("update/reopen generated ceremony artifacts")
		}
	}
	// The released predecessor can reopen this still-unmodified draft safely.
	runRealUpgradeTerminal(t, f.request.Predecessors[d.SourceApp], args, "0\n")
	after, _ = setupFileHash(setup.Draft)
	if before != after {
		t.Fatal("predecessor reentry changed the draft")
	}
	if d.Role == "coordinator" {
		// Real post-update child creation must find its parent through the keys
		// mount, retain the original scratch signer, and use the selected root.
		setupArgs := []string{"ceremony", "setup", "upgrade-keygen-test", "--role", "keygen", "--release", "role-images-" + d.OriginalRelease, "--work", p.Keys, "--settings-root", s.SettingsRoot, "--", "mpc-ceremony", "identity", "generate", "--identity-id", "upgrade-test-coordinator", "--display-name", "Upgrade test", "--private-key-out", "/work/signing.hex", "--public-identity-out", "/work/identity.json"}
		runRealUpgradeTerminal(t, f.request.Candidate, setupArgs, "")
		runRealUpgradeTerminal(t, f.request.Candidate, []string{"ceremony", "open", "upgrade-keygen-test", "--role", "keygen", "--settings-root", s.SettingsRoot}, "y\n")
		var id setupIdentity
		if err := setupReadJSON(filepath.Join(p.Keys, "identity.json"), &id); err != nil {
			t.Fatal(err)
		}
		if err := id.check(); err != nil {
			t.Fatal(err)
		}
		if id.ID != "upgrade-test-coordinator" {
			t.Fatal("wrong generated identity")
		}
		profileDir, _ := guidedDirectory(s.SettingsRoot, "upgrade-keygen-test", "keygen")
		child, err := readGuidedProfile(filepath.Join(profileDir, "profile.json"), "upgrade-keygen-test", "keygen")
		if err != nil {
			t.Fatal(err)
		}
		if child.Image != d.SigningImage || child.ReleaseCommit != d.OriginalRelease {
			t.Fatal("keygen changed the original signing runtime")
		}
	}
}

func TestUpgradeRealTwoPhaseJourney(t *testing.T) {
	f := realUpgradeFixture(t)
	runUpgradeTwoPhaseJourney(t, f, false)
}

func TestUpgradeRealAWSTwoPhaseJourney(t *testing.T) {
	if os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("requires isolated AWS test approval")
	}
	f := realUpgradeFixture(t)
	t.Setenv("RELAY_UPGRADE_LIVE_PROVIDER", "aws")
	t.Setenv("RELAY_AWS_LIVE_CREDENTIALS_FILE", freshAWSLiveCredentials(t))
	runUpgradeTwoPhaseJourney(t, f, false)
}

func runUpgradeTwoPhaseJourney(t *testing.T, f upgradeRealFixture, local bool) {
	d := f.request.Declaration
	// All ordinary live-provider inputs are required, not silently replaced by
	// local handoffs. Missing inputs skip this opt-in test (never qualify a pair).
	required := []string{"RELAY_V4_LIVE_R2_CONFIG", "RELAY_V4_LIVE_R2_CREDENTIALS", "RELAY_V4_LIVE_R2_PARENT", "RELAY_V4_LIVE_R2_CONTROL", "RELAY_V4_LIVE_PROOF_BINARY"}
	if os.Getenv("RELAY_UPGRADE_LIVE_PROVIDER") == "aws" {
		required = []string{"RELAY_V4_LIVE_AWS_CONFIG", "RELAY_AWS_LIVE_CREDENTIALS_FILE", "RELAY_V4_LIVE_PROOF_BINARY"}
	}
	for _, key := range required {
		if os.Getenv(key) == "" {
			t.Skip("isolated live R2 fixture required")
		}
	}
	t.Setenv("RELAY_PREPARE_TEST_IMAGE", d.SigningImage)
	t.Setenv("RELAY_V4_LIVE_ONLINE_IMAGE", d.OriginalImage)
	t.Setenv("RELAY_V4_LIVE_RELAY_BINARY", f.request.Predecessors[d.SourceApp])
	hook := &workflowV4LiveUpgradeHook{Source: f.request.Predecessors[d.SourceApp], Candidate: f.request.Candidate, LocalStorage: local}
	hook.AfterPhase1 = func(role *workflowV4LiveRole) {
		before := map[string]string{}
		for _, path := range []string{filepath.Join(role.profile.Keys, "identity.json"), filepath.Join(role.profile.Keys, "signing.hex"), filepath.Join(role.profile.Work, "ceremony/public/ceremony.json"), filepath.Join(role.profile.Work, "ceremony/public/ceremony.sig")} {
			h, err := setupFileHash(path)
			if err != nil {
				t.Fatal(err)
			}
			before[path] = h
		}
		if err := role.journal.close(); err != nil {
			t.Fatal(err)
		}
		settings := filepath.Join(filepath.Dir(role.profile.Work), "settings")
		role.profile.ReleaseCommit = d.OriginalRelease
		role.signer.ReleaseCommit = d.OriginalRelease
		for _, p := range []guidedProfile{role.profile, role.signer} {
			dir, err := guidedDirectory(settings, p.Name, p.Role)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), p, 0600); err != nil {
				t.Fatal(err)
			}
		}
		guide := []string{"ceremony", "guide", role.profile.Name, "--role", "coordinator", "--settings-root", settings}
		// Both actual applications must open the real signed journal and sync
		// the same cloud checkpoint. No ceremony action is approved by Q.
		if !local {
			runRealUpgradeTerminal(t, f.request.Predecessors[d.SourceApp], guide, "Q\n", 10*time.Minute)
		}
		s := realUpgradeSelection(t, f, role.profile, settings, nil)
		if err := upgradeV2Activate(s, ""); err != nil {
			t.Fatal(err)
		}
		if !local {
			runRealUpgradeTerminal(t, f.request.Candidate, guide, "Q\n", 10*time.Minute)
		}
		// Keep all other roles on the source executable and original images.
		hook.TargetWork = role.profile.Work
		role.profile.UpgradeOnlineImage = d.OnlineImage
		protocol, err := role.inspector.DefinitionProtocol()
		if err != nil {
			t.Fatal(err)
		}
		j, err := openWorkflowV4Journal(protocol, protocol.DefinitionRefs, role.journal.state.Marker.Binding)
		if err != nil {
			t.Fatal(err)
		}
		role.journal = j
		t.Cleanup(func() { _ = j.close() })
		for path, want := range before {
			got, err := setupFileHash(path)
			if err != nil || got != want {
				t.Fatal("update changed original keys or signed ceremony")
			}
		}
	}
	runV4LiveFullR2Journey(t, hook)
}
