package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoordinatorRequiredPrompts(t *testing.T) {
	w := setupFixture(t)
	w.input = bufio.NewReader(strings.NewReader("\n \t\njason\n"))
	value, err := w.required("Display name", "")
	if err != nil || value != "jason" {
		t.Fatal(value, err)
	}
	if strings.Count(w.output.(*bytes.Buffer).String(), "This value is required") != 2 {
		t.Fatal("did not reprompt for blank and whitespace")
	}
	w.input = bufio.NewReader(strings.NewReader("\n"))
	value, err = w.required("Mode", "rehearsal")
	if err != nil || value != "rehearsal" {
		t.Fatal("blank should accept a valid default")
	}
	w.input = bufio.NewReader(strings.NewReader(""))
	if _, err = w.required("Name", ""); err != io.EOF {
		t.Fatal("EOF must stop, not loop", err)
	}
	w.input = bufio.NewReader(strings.NewReader("\n"))
	if err = w.confirm("Sign", "SIGN"); err == nil {
		t.Fatal("blank confirmation must cancel")
	}
}

func TestCoordinatorNumberedChoices(t *testing.T) {
	w := setupFixture(t)
	options := []setupChoice{{"aws", "Amazon S3"}, {"r2", "Cloudflare R2"}}
	w.input = bufio.NewReader(strings.NewReader("\ntext\n0\n3\n2\n"))
	value, err := w.choose("Provider", "", options)
	if err != nil || value != "r2" {
		t.Fatal(value, err)
	}
	w.input = bufio.NewReader(strings.NewReader("\n"))
	value, err = w.choose("Provider", "aws", options)
	if err != nil || value != "aws" {
		t.Fatal("default choice failed", value, err)
	}
	if _, err = w.choose("Empty", "", nil); err == nil {
		t.Fatal("empty choices accepted")
	}
}

func TestCoordinatorParticipantOrderUsesNumbers(t *testing.T) {
	w := setupFixture(t)
	second := w.d.Identities.Roster[0]
	second.Identity.ID = "participant2"
	second.Identity.DisplayName = "Bob"
	w.d.Identities.Roster = append(w.d.Identities.Roster, second)
	w.input = bufio.NewReader(strings.NewReader("1,1\n1,\n3\n2,1\n"))
	order, err := w.participantOrder("Order", nil)
	if err != nil || strings.Join(order, ",") != "participant2,participant1" {
		t.Fatal(order, err)
	}
	w.input = bufio.NewReader(strings.NewReader("\n"))
	order, err = w.participantOrder("Order", order)
	if err != nil || strings.Join(order, ",") != "participant2,participant1" {
		t.Fatal("saved order not preserved", order, err)
	}
}

func TestCoordinatorIdentityConfirmationUsesShortAcknowledgement(t *testing.T) {
	w := setupFixture(t)
	identity := w.d.Identities.Roster[0].Identity
	path := filepath.Join(w.d.Work, "public-identity.json")
	if err := setupWriteNew(path, identity); err != nil {
		t.Fatal(err)
	}
	w.d.Identities.Roster = nil
	w.input = bufio.NewReader(strings.NewReader("4\n" + path + "\n\n"))
	if err := w.identity(); err == nil || len(w.d.Identities.Roster) != 0 {
		t.Fatal("accepted blank confirmation")
	}
	w.input = bufio.NewReader(strings.NewReader("4\n" + path + "\nVERIFIED\n"))
	if err := w.identity(); err != nil {
		t.Fatal(err)
	}
	if len(w.d.Identities.Roster) != 1 {
		t.Fatal("identity not imported")
	}
	output := w.output.(*bytes.Buffer).String()
	if !strings.Contains(output, identity.Fingerprint) || !strings.Contains(output, "type VERIFIED") {
		t.Fatal("missing full fingerprint or short confirmation")
	}
}

func TestCoordinatorIdentityIDIsAutomatic(t *testing.T) {
	w := setupFixture(t)
	if err := os.Remove(filepath.Join(w.d.Keys, "signing.hex")); err != nil {
		t.Fatal(err)
	}
	w.input = bufio.NewReader(strings.NewReader("\n  \njason\nGENERATE\n"))
	var id, display string
	w.localAction = func(_ string, role string, command []string, _ bool) error {
		if role != "keygen" {
			t.Fatal(role)
		}
		for n, arg := range command {
			if arg == "--identity-id" {
				id = command[n+1]
			}
			if arg == "--display-name" {
				display = command[n+1]
			}
		}
		return nil
	}
	if err := w.generateIdentity(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "coordinator-") || !guidedName.MatchString(id) || display != "jason" {
		t.Fatal(id, display)
	}
}

func setupFixture(t *testing.T) coordinatorWizard {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := coordinatorDraft{Schema: "relay-coordinator-draft-v1", Name: "test", Release: "role-images-" + strings.Repeat("a", 40), Work: filepath.Join(root, "work"), Trust: filepath.Join(root, "trust"), Keys: filepath.Join(root, "keys"), Mode: "rehearsal", Circuit: "rehearsal-tiny-v1", Status: "draft", Storage: map[string]string{}}
	for _, p := range []string{d.Work, d.Trust, d.Keys, filepath.Join(d.Work, "coordinator-setup")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	identity := func(id string) setupIdentity {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if id == "coordinator" {
			if err := os.WriteFile(filepath.Join(d.Keys, "signing.hex"), []byte(hex.EncodeToString(key)), 0600); err != nil {
				t.Fatal(err)
			}
		}
		hash := sha256.Sum256(pub)
		return setupIdentity{id, id, id + "-key", hex.EncodeToString(pub), fmt.Sprintf("sha256:%x", hash)}
	}
	d.Identities = setupRoster{identity("coordinator"), identity("signer"), []setupIdentity{identity("auditor1"), identity("auditor2")}, []setupParticipant{{identity("participant1")}}}
	beacon := setupBeacon{Provider: "drand", Network: "quicknet-mainnet", ChainHash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", PublicKey: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a", Scheme: "bls-unchained-g1-rfc9380", Genesis: 1692803367, Period: 3, Extraction: "sha256-domain-separated-length-prefixed-v1", Challenge: 32, Lead: 180, Future: true}
	d.Policy = setupPolicy{setupPhase{[]string{"participant1"}, 1}, setupPhase{[]string{"participant1"}, 1}, beacon}
	return coordinatorWizard{d: d, draftPath: filepath.Join(d.Work, "coordinator-setup", "draft.json"), input: bufio.NewReader(strings.NewReader("")), output: new(bytes.Buffer), run: func([]string) error { return nil }}
}

func TestCoordinatorDraftValidation(t *testing.T) {
	w := setupFixture(t)
	if err := w.d.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*coordinatorDraft){
		func(d *coordinatorDraft) { d.Mode = "production" },
		func(d *coordinatorDraft) { d.Mode = "" },
		func(d *coordinatorDraft) { d.Identities.ReleaseSigner = d.Identities.Coordinator },
		func(d *coordinatorDraft) { d.Identities.Auditors = nil },
		func(d *coordinatorDraft) { d.Policy.Phase1.Minimum = 0 },
		func(d *coordinatorDraft) { d.Policy.Phase1.Participants = []string{"unknown"} },
		func(d *coordinatorDraft) { d.Policy.Phase1.Participants = []string{"participant1", "participant1"} },
		func(d *coordinatorDraft) { d.Policy.Beacon.Future = false },
	} {
		raw, _ := json.Marshal(w.d)
		var d coordinatorDraft
		_ = json.Unmarshal(raw, &d)
		change(&d)
		if err := d.validate(); err == nil {
			t.Fatal("invalid draft accepted")
		}
	}
}

func TestCoordinatorPolicyTemplateMatchesReviewedFixture(t *testing.T) {
	w := setupFixture(t)
	var p setupPolicy
	if err := setupReadJSON("../../release/ceremony-policy.json", &p); err != nil {
		t.Fatal(err)
	}
	if p.Beacon != w.d.Policy.Beacon {
		t.Fatal("beacon template changed without updating the reviewed fixture")
	}
}

func TestCoordinatorVerificationFailureClearsSuccess(t *testing.T) {
	w := setupFixture(t)
	w.d.Status = "definition-verified"
	w.run = func([]string) error { return errors.New("invalid signature") }
	if err := w.verify(); err == nil {
		t.Fatal("accepted verification failure")
	}
	if w.d.Status != "initialization-attempted" {
		t.Fatal("retained success status")
	}
	var saved coordinatorDraft
	if err := setupReadJSON(w.draftPath, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Status != "initialization-attempted" {
		t.Fatal("persisted misleading success")
	}
}

func TestCoordinatorStorageNeedsVerificationAndConsent(t *testing.T) {
	w := setupFixture(t)
	w.d.Storage = map[string]string{"provider": "aws"}
	w.run = func([]string) error { t.Fatal("unapproved storage action"); return nil }
	if err := w.configureStorage(); err == nil {
		t.Fatal("configured before verification")
	}
	w.d.Status = "definition-verified"
	w.input = bufio.NewReader(strings.NewReader("no\n"))
	if err := w.configureStorage(); err == nil {
		t.Fatal("configured without consent")
	}
}
func TestCoordinatorDraftRoundTripAndStrictInputs(t *testing.T) {
	w := setupFixture(t)
	if err := w.save(); err != nil {
		t.Fatal(err)
	}
	var d coordinatorDraft
	if err := setupReadJSON(w.draftPath, &d); err != nil {
		t.Fatal(err)
	}
	if d.Identities.Coordinator != w.d.Identities.Coordinator {
		t.Fatal("identity changed")
	}
	info, _ := os.Stat(w.draftPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("draft not private")
	}
	for _, raw := range []string{`{"id":"x","id":"y"}`, `{"private_key":"secret"}`, `{} {}`} {
		path := filepath.Join(w.d.Work, "invalid.json")
		_ = os.WriteFile(path, []byte(raw), 0600)
		var i setupIdentity
		if err := setupReadJSON(path, &i); err == nil {
			t.Fatal("accepted malformed identity")
		}
	}
	link := filepath.Join(w.d.Work, "linked.json")
	_ = os.Symlink(w.draftPath, link)
	if err := setupReadJSON(link, &d); err == nil {
		t.Fatal("followed input symlink")
	}
}
func TestCoordinatorPostInitializationMenu(t *testing.T) {
	for _, tc := range []struct {
		name, status, heading string
		local, storage        bool
	}{
		{"verified", "definition-verified", "Initialization complete", false, true},
		{"local", "definition-verified", "Local setup test complete", true, false},
		{"interrupted", "initialization-attempted", "Initialization needs verification", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := setupFixture(t)
			w.d.Status = tc.status
			if tc.local {
				w.localAction = func(string, string, []string, bool) error { t.Fatal("unexpected action"); return nil }
			}
			w.input = bufio.NewReader(strings.NewReader("0\n"))
			if err := w.menu(); err != nil {
				t.Fatal(err)
			}
			out := w.output.(*bytes.Buffer).String()
			for _, hidden := range []string{"1 Basics", "2 Generate", "3 Import", "4 Orders", "5 Add", "8 Approve", "11 Remove", "Coordinator preparation"} {
				if strings.Contains(out, hidden) {
					t.Fatalf("stale action %q in %s", hidden, out)
				}
			}
			for _, visible := range []string{tc.heading, "7 Review identities and policy", "9 Verify existing definition", "0 Save and exit"} {
				if !strings.Contains(out, visible) {
					t.Fatalf("missing %q", visible)
				}
			}
			if strings.Contains(out, "10 Configure storage") != tc.storage {
				t.Fatal("incorrect storage availability")
			}
		})
	}
}

func TestCoordinatorInitializationRequiresConsentAndFreezesOnFailure(t *testing.T) {
	w := setupFixture(t)
	calls := 0
	w.run = func([]string) error { calls++; return errors.New("simulated failure") }
	w.input = bufio.NewReader(strings.NewReader("no\n"))
	if err := w.initialize(); err == nil || calls != 0 || w.d.Status != "draft" {
		t.Fatal("initialized without consent")
	}
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	if err := w.initialize(); err == nil || calls != 1 || w.d.Status != "initialization-attempted" {
		t.Fatal("uncertain attempt not frozen")
	}
	if err := w.initialize(); err == nil || calls != 1 {
		t.Fatal("repeated uncertain initialization")
	}
	var frozen coordinatorDraft
	if err := setupReadJSON(filepath.Join(w.d.Work, "coordinator-setup", "frozen", "draft.json"), &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.CreatedAt == "" {
		t.Fatal("missing frozen creation time")
	}
	w.input = bufio.NewReader(strings.NewReader("1\n0\n"))
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	if w.d.Mode != "rehearsal" {
		t.Fatal("edited frozen draft")
	}
}
func TestCoordinatorInitializationUsesProofToolAndExternalTrust(t *testing.T) {
	w := setupFixture(t)
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	var calls [][]string
	w.run = func(args []string) error { calls = append(calls, args); return nil }
	if err := w.initialize(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 || w.d.Status != "definition-verified" {
		t.Fatal(calls, w.d.Status)
	}
	joined := strings.Join(calls[0], " ")
	for _, s := range []string{"mpc-ceremony init --mode rehearsal", "--key-version rehearsal-tiny-v1", "--coordinator-signing-key /keys/signing.hex", "--out-dir /work/ceremony/public"} {
		if !strings.Contains(joined, s) {
			t.Fatal(joined)
		}
	}
	if !strings.Contains(strings.Join(calls[2], " "), "--coordinator-public-key-file /trust/setup-coordinator.hex") {
		t.Fatal("missing independent trust anchor")
	}
}
func TestCoordinatorChangedAllowlistBinaryStopsBeforeExecution(t *testing.T) {
	w := setupFixture(t)
	path := filepath.Join(w.d.Work, "tool")
	_ = os.WriteFile(path, []byte("changed"), 0600)
	w.d.Binaries = []setupBinary{{path, strings.Repeat("0", 64)}}
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	w.run = func([]string) error { t.Fatal("executed changed binary policy"); return nil }
	if err := w.initialize(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal(err)
	}
}

// Opt-in real tiny initialization. Fixture keys are generated only in the
// temporary test directory. No participants contribute and nothing is uploaded.
func TestCoordinatorPrepareDocker(t *testing.T) {
	image := os.Getenv("RELAY_PREPARE_TEST_IMAGE")
	if image == "" {
		t.Skip("set RELAY_PREPARE_TEST_IMAGE to an existing immutable test image")
	}
	w := setupFixture(t)
	w.input = bufio.NewReader(strings.NewReader("INITIALIZE REHEARSAL\n"))
	var command []string
	w.run = func(args []string) error {
		if args[1] == "setup" {
			for n, a := range args {
				if a == "--" {
					command = append([]string(nil), args[n+1:]...)
					return nil
				}
			}
			return errors.New("missing tool command")
		}
		platform, err := machineDockerPlatform()
		if err != nil {
			return err
		}
		argv, err := dockerRoleArgs(dockerRoleOptions{role: "coordinator", image: image, platform: platform, work: w.d.Work, trust: w.d.Trust, keys: w.d.Keys}, command, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		out, err := exec.Command("docker", argv...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	if err := w.initialize(); err != nil {
		t.Fatal(err)
	}
	if w.d.Status != "definition-verified" {
		t.Fatal(w.d.Status)
	}
	for _, name := range []string{"ceremony.json", "ceremony.sig", "phase1"} {
		if _, err := os.Stat(filepath.Join(w.d.Work, "ceremony", "public", name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w.d.Work, "ceremony", "public", "ceremony.sig"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.verify(); err == nil {
		t.Fatal("real proof-tool accepted corrupted signature")
	}
	if w.d.Status != "initialization-attempted" {
		t.Fatal("kept verified status after corrupted signature")
	}
}
