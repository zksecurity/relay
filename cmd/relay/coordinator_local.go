//go:build relaylocal

package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func init() { coordinatorLocalRunner = runCoordinatorLocal }

func localTestCommandAllowed(role string, command []string, credentials bool) bool {
	if credentials || len(command) < 3 || command[0] != "mpc-ceremony" {
		return false
	}
	if role == "keygen" {
		return command[1] == "identity" && command[2] == "generate"
	}
	if role != "coordinator" {
		return false
	}
	if command[1] == "inspect" && command[2] == "definition" {
		return true
	}
	if command[1] != "init" {
		return false
	}
	value := func(flag string) string {
		for n, a := range command {
			if a == flag && n+1 < len(command) {
				return command[n+1]
			}
		}
		return ""
	}
	return value("--mode") == "rehearsal" && value("--key-version") == "rehearsal-tiny-v1" && !slices.Contains(command, "--allowed-binary")
}

func runCoordinatorLocal(args []string) error {
	flags := flag.NewFlagSet("prepare-local", flag.ContinueOnError)
	root := flags.String("root", "", "dedicated local-test directory")
	newIdentity := flags.Bool("new-identity", false, "generate a separate TEST role identity for manual import")
	clearMocks := flags.Bool("clear-mocks", false, "remove only legacy mock assignments from an unsigned local draft")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root || (*newIdentity && *clearMocks) {
		return errors.New("absolute clean --root required")
	}
	if err := ensurePrivateDirectory(*root); err != nil {
		return err
	}
	platform, err := machineDockerPlatform()
	if err != nil {
		return err
	}
	images := map[string]string{}
	for _, role := range []string{"online", "offline"} {
		path := filepath.Join(*root, role+"-image.txt")
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Size() > 128 {
			return errors.New("invalid local image record")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		id := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(id, "sha256:") || !roleImagePattern.MatchString(id) {
			return errors.New("local images must be immutable image IDs")
		}
		if err := prepareGuidedImage(id, platform, "docker", false); err != nil {
			return err
		}
		images[role] = id
	}
	run := executeGuidedChild
	if *newIdentity {
		return generateLocalRoleIdentity(*root, images["offline"], run, os.Stdin, os.Stdout)
	}
	d := coordinatorDraft{Schema: "relay-coordinator-draft-v1", Name: "local-test", Release: "LOCAL-REHEARSAL", Work: filepath.Join(*root, "work"), Trust: filepath.Join(*root, "trust"), Keys: filepath.Join(*root, "keys"), Status: "draft", Mode: "rehearsal", Circuit: "rehearsal-tiny-v1", Storage: map[string]string{}, PolicyTemplate: filepath.Join(*root, "ceremony-policy.json")}
	for _, path := range []string{d.Work, d.Trust, d.Keys, filepath.Join(d.Work, "coordinator-setup")} {
		if err := ensurePrivateDirectory(path); err != nil {
			return err
		}
	}
	draftPath := filepath.Join(d.Work, "coordinator-setup", "draft.json")
	lock, err := acquireParticipantRunLock(draftPath, filepath.Dir(draftPath))
	if err != nil {
		return err
	}
	defer lock.release()
	fmt.Println("LOCAL TEST ONLY — no release provenance approval, no production circuit, no cloud operations.")
	if _, err := os.Lstat(draftPath); err == nil {
		var saved coordinatorDraft
		if err := setupReadJSON(draftPath, &saved); err != nil {
			return err
		}
		if saved.Schema != d.Schema || saved.Name != d.Name || saved.Release != d.Release || saved.Work != d.Work || saved.Trust != d.Trust || saved.Keys != d.Keys || saved.Mode != "rehearsal" || saved.Circuit != "rehearsal-tiny-v1" {
			return errors.New("saved local draft does not match this test directory")
		}
		d = saved
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		fmt.Println("Starting with an empty roster. Generate separate TEST role identities and manually import their public identity.json files.")
		if err := saveCoordinatorDraft(draftPath, d); err != nil {
			return err
		}
	}
	w := coordinatorWizard{d: d, input: bufio.NewReader(os.Stdin), output: os.Stdout, draftPath: draftPath}
	if *clearMocks {
		if d.Status != "draft" {
			return errors.New("cannot remove assignments after initialization was attempted")
		}
		if err := w.confirm("Remove legacy mock assignments and affected phase orders? Your coordinator identity, real imports, keys and other files are preserved", "REMOVE MOCK ASSIGNMENTS"); err != nil {
			return err
		}
		count, err := clearLocalMockAssignments(&w.d)
		if err != nil {
			return err
		}
		if err := w.save(); err != nil {
			return err
		}
		fmt.Printf("Removed %d mock assignments from the unsigned draft. No files or keys were deleted. Import your test identities, then review both phase orders.\n", count)
		return nil
	}
	settings := filepath.Join(*root, "launcher-settings")
	w.continueFlow = func() error {
		name := "local-ceremony-workflow"
		profilePath := filepath.Join(settings, name, "coordinator", "profile.json")
		if _, err := os.Lstat(profilePath); errors.Is(err, os.ErrNotExist) {
			if err := run([]string{"ceremony", "setup", name, "--settings-root", settings, "--role", "coordinator", "--image", images["online"], "--download=false", "--work", d.Work, "--trust", d.Trust, "--keys", d.Keys}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		p, err := readGuidedProfile(profilePath, name, "coordinator")
		if err != nil {
			return err
		}
		if p.Image != images["online"] || p.Work != d.Work || p.Trust != d.Trust || p.Keys != d.Keys || p.Credentials != "" {
			return errors.New("local workflow profile changed")
		}
		fmt.Println("This existing local ceremony can continue through the role workflow. Cloud transport still needs separately provisioned rehearsal storage; do not use production credentials.")
		return run([]string{"ceremony", "guide", name, "--role", "coordinator", "--settings-root", settings})
	}
	w.localAction = func(name, role string, command []string, credentials bool) error {
		if !localTestCommandAllowed(role, command, credentials) {
			return errors.New("operation disabled in local test harness")
		}
		image := images["online"]
		if role == "keygen" {
			image = images["offline"]
		}
		encoded := strings.Join(command, "\x00") + image
		digest := sha256.Sum256([]byte(encoded))
		alias := fmt.Sprintf("local-%s-%x", name, digest[:8])
		work, trust, keys := d.Work, d.Trust, d.Keys
		if role == "keygen" {
			work, trust, keys = d.Keys, "", ""
		}
		setup := []string{"ceremony", "setup", alias, "--settings-root", settings, "--role", role, "--image", image, "--download=false", "--work", work}
		if trust != "" {
			setup = append(setup, "--trust", trust, "--keys", keys)
		}
		setup = append(setup, "--")
		setup = append(setup, command...)
		profilePath := filepath.Join(settings, alias, role, "profile.json")
		open := []string{"ceremony", "open", alias, "--settings-root", settings, "--role", role}
		if _, err := os.Lstat(profilePath); errors.Is(err, os.ErrNotExist) {
			if err := run(setup); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			p, err := readGuidedProfile(profilePath, alias, role)
			if err != nil {
				return err
			}
			if p.Image != image || p.ReleaseCommit != "" || p.Work != work || p.Keys != keys || p.Credentials != "" || !slices.Equal(p.Command, command) || (role != "keygen" && p.Trust != trust) {
				return errors.New("saved local action changed")
			}
			if err := checkGuidedAttempts(filepath.Join(settings, alias, role, "activity")); err != nil && !errors.Is(err, os.ErrNotExist) {
				if err := w.confirm("Review earlier failed/interrupted local action before retrying", "REVIEWED RETRY"); err != nil {
					return err
				}
				open = append(open, "--reviewed-retry")
			}
		}
		return run(open)
	}
	return w.menu()
}

func clearLocalMockAssignments(d *coordinatorDraft) (int, error) {
	if d.Release != "LOCAL-REHEARSAL" || d.Status != "draft" {
		return 0, errors.New("only unsigned local drafts can be changed")
	}
	removed := map[string]bool{}
	mock := func(i setupIdentity) bool {
		if (i.ID == "signer" || i.ID == "auditor1" || i.ID == "auditor2" || i.ID == "participant1") && i.DisplayName == "MOCK "+i.ID && i.KeyID == i.ID+"-key" {
			removed[i.ID] = true
			return true
		}
		return false
	}
	if mock(d.Identities.ReleaseSigner) {
		d.Identities.ReleaseSigner = setupIdentity{}
	}
	auditors := []setupIdentity{}
	for _, i := range d.Identities.Auditors {
		if !mock(i) {
			auditors = append(auditors, i)
		}
	}
	d.Identities.Auditors = auditors
	roster := []setupParticipant{}
	for _, p := range d.Identities.Roster {
		if !mock(p.Identity) {
			roster = append(roster, p)
		}
	}
	d.Identities.Roster = roster
	for _, phase := range []*setupPhase{&d.Policy.Phase1, &d.Policy.Phase2} {
		for _, id := range phase.Participants {
			if removed[id] {
				*phase = setupPhase{}
				break
			}
		}
	}
	return len(removed), nil
}

func generateLocalRoleIdentity(root, image string, run func([]string) error, input io.Reader, output io.Writer) error {
	w := coordinatorWizard{input: bufio.NewReader(input), output: output}
	fmt.Fprintln(output, "TEST IDENTITY ONLY. This simulates a separate role's machine; do not use these keys for production.")
	role, err := w.choose("Test role", "", []setupChoice{{"participant", "Participant"}, {"auditor", "Auditor"}, {"release-signer", "Final-parameter signer"}})
	if err != nil {
		return err
	}
	switch role {
	case "participant", "auditor", "release-signer":
	default:
		return errors.New("choose participant, auditor or release-signer")
	}
	display, err := w.required("Public display name", "")
	if err != nil {
		return err
	}
	suffix, err := randomID()
	if err != nil {
		return err
	}
	id := role + "-" + suffix
	roleRoot := filepath.Join(root, "test-roles", id)
	keys := filepath.Join(roleRoot, "keys")
	fmt.Fprintf(output, "Identity ID: %s\nSeparate role folder: %s\n", id, roleRoot)
	if err := w.confirm("Generate a test keypair in the offline Docker image", "GENERATE"); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(filepath.Join(root, "test-roles")); err != nil {
		return err
	}
	if err := os.Mkdir(roleRoot, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(keys, 0700); err != nil {
		return err
	}
	alias := "test-identity-" + suffix
	settings := filepath.Join(root, "test-role-settings")
	args := []string{"ceremony", "setup", alias, "--role", "keygen", "--settings-root", settings, "--image", image, "--download=false", "--work", keys, "--", "mpc-ceremony", "identity", "generate", "--identity-id", id, "--display-name", display, "--private-key-out", "/work/signing.hex", "--public-identity-out", "/work/identity.json"}
	if err := run(args); err != nil {
		return err
	}
	if err := run([]string{"ceremony", "open", alias, "--role", "keygen", "--settings-root", settings}); err != nil {
		return err
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(keys, "identity.json"), &identity); err != nil {
		return err
	}
	if err := identity.check(); err != nil {
		return err
	}
	if identity.ID != id || identity.DisplayName != display {
		return errors.New("generated public identity does not match the requested values")
	}
	fmt.Fprintf(output, "\nSend/import ONLY this public file as %s:\n%s\nFingerprint to confirm through the independent channel:\n%s\nKeep signing.hex in this separate role folder; never copy it to the coordinator.\n", role, filepath.Join(keys, "identity.json"), identity.Fingerprint)
	return nil
}
