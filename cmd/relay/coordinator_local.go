//go:build relaylocal

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root {
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
		// Mock public identities are only for initialization. Their signing keys
		// are discarded; they cannot be used to conduct a complete real ceremony.
		mock := func(id string) (setupIdentity, error) {
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return setupIdentity{}, err
			}
			hash := sha256.Sum256(public)
			return setupIdentity{ID: id, DisplayName: "MOCK " + id, KeyID: id + "-key", PublicKey: hex.EncodeToString(public), Fingerprint: fmt.Sprintf("sha256:%x", hash)}, nil
		}
		signer, err := mock("signer")
		if err != nil {
			return err
		}
		d.Identities.ReleaseSigner = signer
		for _, id := range []string{"auditor1", "auditor2"} {
			i, err := mock(id)
			if err != nil {
				return err
			}
			d.Identities.Auditors = append(d.Identities.Auditors, i)
		}
		i, err := mock("participant1")
		if err != nil {
			return err
		}
		d.Identities.Roster = []setupParticipant{{Identity: i}}
		fmt.Println("Added MOCK public identities for two auditors, one final-parameter signer, and one participant. Generate/import your TEST coordinator identity using the menu.")
		if err := saveCoordinatorDraft(draftPath, d); err != nil {
			return err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	run := func(args []string) error {
		cmd := exec.Command(executable, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	w := coordinatorWizard{d: d, input: bufio.NewReader(os.Stdin), output: os.Stdout, draftPath: draftPath}
	settings := filepath.Join(*root, "launcher-settings")
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
