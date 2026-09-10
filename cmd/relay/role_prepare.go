package main

// Onboarding collects paths and invokes existing authenticated commands. It
// measures pinned tools but does not issue enrollments or implement protocol crypto.
import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type rolePreparation struct {
	Schema, Name, Role, Release, Work, Trust, Keys string
	Values                                         map[string]string
}
type rolePreparer struct {
	d                    rolePreparation
	path, settingsRoot   string
	ui                   coordinatorWizard
	run                  func([]string) error
	environmentPreflight func() error // test seam; nil uses the actual Docker preflight
}

func (p *rolePreparer) save() error { return saveJSONAtomic(p.path, p.d) }
func (p *rolePreparer) alias(role string) string {
	if role == "decision-signer" {
		return offlineRoleAlias(p.d.Name, p.d.Role)
	}
	if role == "keygen" {
		// Several roles may share a local ceremony name, but never a key profile.
		return fmt.Sprintf("identity-%x", sha256.Sum256([]byte(p.d.Name+"\x00"+p.d.Role+"\x00"+p.d.Keys)))[:49]
	}
	return p.d.Name
}
func (p *rolePreparer) value(key, label, fallback string) (string, error) {
	if old := p.d.Values[key]; old != "" {
		fallback = old
	}
	v, err := p.ui.required(label, fallback)
	if err != nil {
		return "", err
	}
	p.d.Values[key] = v
	return v, p.save()
}
func (p *rolePreparer) profile(role string) (guidedProfile, error) {
	dir, err := guidedDirectory(p.settingsRoot, p.alias(role), role)
	if err != nil {
		return guidedProfile{}, err
	}
	v, err := readGuidedProfile(filepath.Join(dir, "profile.json"), p.alias(role), role)
	if err != nil {
		return v, err
	}
	work, keys := p.d.Work, p.d.Keys
	if role == "keygen" {
		work, keys = p.d.Keys, ""
	}
	if role == "upload-station" || role == "witness" || role == "mirror" {
		keys = ""
	}
	if v.ReleaseCommit != strings.TrimPrefix(p.d.Release, "role-images-") || len(v.Command) != 0 || v.Credentials != "" {
		return v, errors.New("saved profile differs from this preparation")
	}
	if role == "participant" {
		if v.Config != filepath.Join(p.d.Work, "ceremony/config/participant-phase1.json") {
			return v, errors.New("unexpected participant profile")
		}
	} else if v.Work != work || v.Keys != keys || (role != "keygen" && v.Trust != p.d.Trust) {
		return v, errors.New("saved profile uses different role directories")
	}
	return v, nil
}
func (p *rolePreparer) setup(role string) error {
	dir, err := guidedDirectory(p.settingsRoot, p.alias(role), role)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err == nil {
		_, err = p.profile(role)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	args := []string{"ceremony", "setup", p.alias(role), "--settings-root", p.settingsRoot, "--role", role, "--release", p.d.Release}
	switch role {
	case "participant":
		args = append(args, "--config", filepath.Join(p.d.Work, "ceremony/config/participant-phase1.json"))
	case "keygen":
		args = append(args, "--work", p.d.Keys)
	default:
		args = append(args, "--work", p.d.Work, "--trust", p.d.Trust)
		if role != "upload-station" && role != "witness" && role != "mirror" {
			args = append(args, "--keys", p.d.Keys)
		}
	}
	return p.run(args)
}
func (p *rolePreparer) open(role, action string, command []string) error {
	if _, err := p.profile(role); err != nil {
		return fmt.Errorf("prepare the approved images first: %w", err)
	}
	dir, _ := guidedDirectory(p.settingsRoot, p.alias(role), role)
	args := []string{"ceremony", "open", p.alias(role), "--settings-root", p.settingsRoot, "--role", role, "--action", action}
	if err := checkGuidedAttempts(filepath.Join(dir, "actions", action, "activity")); err != nil && !errors.Is(err, os.ErrNotExist) {
		if err := p.ui.confirm("Review the interrupted action, retained outputs and container state; do not overwrite or replace signed files", "REVIEWED RETRY"); err != nil {
			return err
		}
		args = append(args, "--reviewed-retry")
	}
	args = append(args, "--")
	args = append(args, command...)
	return p.run(args)
}
func (p *rolePreparer) images() error {
	if p.d.Role != "upload-station" {
		if err := p.setup("keygen"); err != nil {
			return err
		}
		if err := p.setup("decision-signer"); err != nil {
			return err
		}
	}
	if p.d.Role == "participant" {
		platform, err := machineDockerPlatform()
		if err != nil {
			return err
		}
		image, _, err := verifiedReleaseImage(p.d.Release, "participant", platform)
		if err != nil {
			return err
		}
		if err := prepareGuidedImage(image, platform, "docker", true); err != nil {
			return err
		}
		p.d.Values["image"], p.d.Values["platform"] = image, platform
		return p.prepareToolReceipt()
	}
	if err := p.setup(p.d.Role); err != nil {
		return err
	}
	return p.prepareToolReceipt()
}
func (p *rolePreparer) identity() error {
	if p.d.Role == "upload-station" {
		return errors.New("upload stations do not generate or receive signing keys")
	}
	public := filepath.Join(p.d.Keys, "identity.json")
	if _, err := os.Lstat(public); err == nil {
		var id setupIdentity
		if err := setupReadJSON(public, &id); err != nil {
			return err
		}
		if err := id.check(); err != nil {
			return err
		}
		fmt.Fprintf(p.ui.output, "Existing public identity: %s (%s). Send ONLY %s to the coordinator. No key was generated.\n", id.DisplayName, id.ID, public)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(p.d.Keys, "signing.hex")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("private key already exists or cannot be inspected; preserve it and investigate, never regenerate automatically")
	}
	id := p.d.Values["identity-id"]
	if id == "" {
		suffix, err := randomID()
		if err != nil {
			return err
		}
		id = p.d.Role + "-" + suffix
		p.d.Values["identity-id"] = id
	}
	display, err := p.value("display-name", "Your public display name", "")
	if err != nil {
		return err
	}
	if p.d.Role == "release-signer" {
		if err := p.ui.confirm("Disconnect the signing machine from networks now; the images must already be prepared", "OFFLINE"); err != nil {
			return err
		}
	}
	if err := p.ui.confirm("Generate only YOUR keypair; the public identity ID is "+id, "GENERATE"); err != nil {
		return err
	}
	err = p.open("keygen", "identity", []string{"mpc-ceremony", "identity", "generate", "--identity-id", id, "--display-name", display, "--private-key-out", "/work/signing.hex", "--public-identity-out", "/work/identity.json"})
	if err == nil {
		fmt.Fprintf(p.ui.output, "Send ONLY %s to the coordinator through your agreed channel. Keep signing.hex private.\n", public)
	}
	return err
}

// Fixed destinations prevent a received filename from selecting a key or saved
// settings path. Importing public bytes is not authenticating their signatures.
func preparationImports() []setupChoice {
	return []setupChoice{{"definition", "Signed ceremony definition"}, {"signature", "Definition signature"}, {"coordinator", "Independently obtained coordinator public key"}, {"storage", "Public storage configuration (not credentials)"}, {"enrollment", "Your reviewed public enrollment"}, {"enrollment-signature", "Your enrollment signature"}, {"receipt", "Advanced: existing tool record for this exact installation"}}
}
func preparationDestination(d rolePreparation, kind string) string {
	switch kind {
	case "definition":
		return filepath.Join(d.Work, "ceremony/public/ceremony.json")
	case "signature":
		return filepath.Join(d.Work, "ceremony/public/ceremony.sig")
	case "coordinator":
		return filepath.Join(d.Trust, "coordinator-public-key.hex")
	case "storage":
		return filepath.Join(d.Work, "ceremony/config/relay-storage.json")
	case "enrollment":
		return filepath.Join(d.Work, "enrollment.json")
	case "enrollment-signature":
		return filepath.Join(d.Work, "enrollment.sig")
	case "receipt":
		return filepath.Join(d.Trust, "tool-identity-receipt.env")
	}
	return ""
}
func readPreparationInput(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("use an absolute clean file path")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, errors.New("use a regular public file under 1 MiB, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("input changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(raw) > 1<<20 {
		return nil, errors.New("input too large")
	}
	return raw, err
}
func (p *rolePreparer) importFile() error {
	kind, err := p.ui.choose("Which PUBLIC file are you importing?", "", preparationImports())
	if err != nil {
		return err
	}
	source, err := p.ui.required("Absolute path to the public file (never a signing key or grant)", "")
	if err != nil {
		return err
	}
	raw, err := readPreparationInput(source)
	if err != nil {
		return err
	}
	if kind == "coordinator" {
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return errors.New("expected a 32-byte public key encoded as hex")
		}
		fmt.Fprintf(p.ui.output, "Coordinator public-key fingerprint: sha256:%x\n", sha256.Sum256(key))
		if err := p.ui.confirm("Compare this fingerprint with the coordinator over your independent channel, not the file's download page", "VERIFIED"); err != nil {
			return err
		}
	} else if kind != "receipt" && !json.Valid(raw) {
		return errors.New("expected the public JSON artifact, not a private key or raw signature")
	}
	dest := preparationDestination(p.d, kind)
	fmt.Fprintf(p.ui.output, "Public input: %s\nSHA-256: %x\nDestination: %s\nImport does not verify the ceremony or an enrollment signature.\n", source, sha256.Sum256(raw), dest)
	if err := p.ui.confirm("Confirm the file is the indicated public artifact; a receipt must come from authenticated setup for these exact tools", "IMPORT"); err != nil {
		return err
	}
	if old, err := readPreparationInput(dest); err == nil {
		if string(old) == string(raw) {
			fmt.Fprintln(p.ui.output, "Identical file already present; left unchanged.")
			return nil
		}
		return errors.New("destination already contains different bytes; preserve them and investigate")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (p *rolePreparer) initProfile() error {
	role := p.d.Role
	if role == "release-signer" {
		return errors.New("offline final-parameter signing uses the prepared workflow directly, not a transport profile")
	}
	if role == "upload-station" {
		role = "release"
	}
	if role != "participant" {
		for _, name := range []string{"enrollment.json", "enrollment.sig"} {
			if _, err := readPreparationInput(filepath.Join(p.d.Work, name)); err != nil {
				if role == "release" {
					return errors.New("import the final signer's public enrollment and signature using option 3 first; this upload station must not sign them")
				}
				return errors.New("prepare and sign your own enrollment with option 7 first, after importing the signed definition and trusted coordinator key")
			}
		}
	}
	phase, err := p.ui.choose("Phase for this profile", "phase1", []setupChoice{{"phase1", "Phase 1"}, {"phase2", "Phase 2"}})
	if err != nil {
		return err
	}
	home, trust, work := "/work/ceremony", "/trust", "/work"
	if role == "participant" {
		home, trust, work = filepath.Join(p.d.Work, "ceremony"), p.d.Trust, p.d.Work
	}
	out := filepath.Join(home, "config", role+"-"+phase+".json")
	args := []string{"relay", "ceremony", "init-config", "--home", home, "--role", role, "--phase", phase, "--coordinator-key", filepath.Join(trust, "coordinator-public-key.hex"), "--tool-identity-receipt", filepath.Join(trust, "tool-identity-receipt.env"), "--out", out}
	if role != "release" {
		var id setupIdentity
		if err := setupReadJSON(filepath.Join(p.d.Keys, "identity.json"), &id); err != nil {
			return fmt.Errorf("generate your identity first: %w", err)
		}
		if err := id.check(); err != nil {
			return err
		}
		args = append(args, "--identity", id.ID)
	}
	if role == "participant" {
		image, platform := p.d.Values["image"], p.d.Values["platform"]
		if !roleImagePattern.MatchString(image) || (platform != "linux/amd64" && platform != "linux/arm64") {
			return errors.New("prepare and verify the contributor image first")
		}
		binary := p.d.Values["binary"]
		if binary == "" {
			return errors.New("prepare approved images and tools first")
		}
		env, err := p.environment()
		if err != nil {
			return err
		}
		args = append(args, "--execution-mode", "docker", "--docker-image", image, "--docker-platform", platform, "--ceremony-binary", binary, "--signing-key", filepath.Join(p.d.Keys, "signing.hex"), "--environment", env)
		fmt.Fprintf(p.ui.output, "Authenticate tools, signed definition and YOUR assignment; create fresh profile: %s\n", out)
		if err := p.ui.confirm("Check your environment statements are true before continuing", "REVIEWED"); err != nil {
			return err
		}
		return p.run(args[1:])
	}
	args = append(args, "--enrollment", filepath.Join(work, "enrollment.json"), "--enrollment-signature", filepath.Join(work, "enrollment.sig"))
	return p.open(p.d.Role, "profile-"+phase, args)
}
func (p *rolePreparer) workflow() error {
	if p.d.Role == "participant" {
		if err := p.setup("participant"); err != nil {
			return err
		}
	}
	if _, err := p.profile(p.d.Role); err != nil {
		return err
	}
	return p.run([]string{"ceremony", "guide", p.d.Name, "--role", p.d.Role, "--settings-root", p.settingsRoot})
}
func (p *rolePreparer) menu() error {
	for {
		p.ui.message(toneHeading, "\n%s — %s onboarding\n", p.d.Name, p.d.Role)
		fmt.Fprintln(p.ui.output, "1) Prepare approved images (online; before disconnecting a signer)")
		if p.d.Role != "upload-station" {
			fmt.Fprintln(p.ui.output, "2) Generate/review MY identity and public handoff")
		}
		fmt.Fprintln(p.ui.output, "3) Import a received public file")
		if p.d.Role != "release-signer" {
			fmt.Fprintln(p.ui.output, "4) Authenticate and create a phase profile")
		}
		fmt.Fprintln(p.ui.output, "5) Open ceremony operations and progress\n6) Show folders and remaining input requirements")
		if p.d.Role != "upload-station" {
			fmt.Fprintln(p.ui.output, "7) Prepare, review and sign MY enrollment (after receiving the signed definition)")
		}
		fmt.Fprintln(p.ui.output, "8) Show all setup steps (including those that do not apply)\n0) Save and exit")
		choice, err := p.ui.ask("Choose", "0")
		if err != nil {
			return err
		}
		if reason := onboardingNotApplicable(p.d.Role, choice); reason != "" {
			fmt.Fprintf(p.ui.output, "Not applicable: %s\n", reason)
			continue
		}
		switch choice {
		case "0":
			return p.save()
		case "1":
			err = p.images()
		case "2":
			err = p.identity()
		case "3":
			err = p.importFile()
		case "4":
			err = p.initProfile()
		case "5":
			err = p.workflow()
		case "6":
			fmt.Fprintf(p.ui.output, "Work/public outputs: %s\nTrusted public files: %s\nPRIVATE keys: %s\nObtain signed ceremony files and public storage configuration through the agreed channel. Prepare approved images to create your local tool record. Participant environment questions are included in profile setup. Use option 7 for your own enrollment; upload stations instead import the final signer's public enrollment. Witness/mirror receipts are reviewed and signed with the offline image in the workflow. Disconnect the signing host when prompted. Complete phase transcripts and operational evidence are exchanged separately; importing a definition does not fetch them.\n", p.d.Work, p.d.Trust, p.d.Keys)
		case "7":
			err = p.enroll()
		case "8":
			for n, label := range []string{"Prepare approved images", "Generate/review MY identity", "Import a public file", "Create a phase profile", "Open the ceremony workflow", "Show folders and requirements", "Prepare and sign MY enrollment"} {
				status := "Applies; prerequisites may still be missing"
				if reason := onboardingNotApplicable(p.d.Role, fmt.Sprint(n+1)); reason != "" {
					status = "Not applicable: " + reason
				}
				fmt.Fprintf(p.ui.output, "- %s — %s\n", label, status)
			}
		default:
			err = errors.New("choose a listed number")
		}
		if err != nil {
			p.ui.message(toneError, "Stopped: %v\nSaved state and outputs retained. Resolve the cause; do not bypass verification.\n", err)
		}
	}
}

func onboardingNotApplicable(role, choice string) string {
	if role == "upload-station" && (choice == "2" || choice == "7") {
		return "Upload stations do not own signing keys; import the final signer's public enrollment instead."
	}
	if role == "release-signer" && choice == "4" {
		return "Final signers use the offline signing workflow, not an online transport phase profile."
	}
	return ""
}

func runRolePrepare(args []string) error {
	d := rolePreparation{Schema: "relay-role-preparation-v1", Values: map[string]string{}}
	f := flag.NewFlagSet("ceremony prepare", flag.ContinueOnError)
	f.StringVar(&d.Name, "name", "", "local ceremony name")
	f.StringVar(&d.Role, "role", "", "ceremony role")
	f.StringVar(&d.Release, "release", "", "exact approved release")
	f.StringVar(&d.Work, "work", "", "work folder")
	f.StringVar(&d.Trust, "trust", "", "public trust folder")
	f.StringVar(&d.Keys, "keys", "", "protected key folder")
	if err := f.Parse(args); err != nil {
		return err
	}
	if len(f.Args()) != 0 || !guidedName.MatchString(d.Name) || !launcherReleaseTag.MatchString(d.Release) || d.Role == "coordinator" || len(roleFlowStages(d.Role)) == 0 {
		return errors.New("supply a valid name, exact release and non-coordinator role; coordinators use coordinator prepare")
	}
	if err := checkLauncherRelease(strings.TrimPrefix(d.Release, "role-images-")); err != nil {
		return err
	}
	for _, dir := range []string{d.Work, d.Trust, d.Keys} {
		if err := validateRoleMount(dir, false); err != nil {
			return err
		}
	}
	// Validate disjoint mounts before creating any onboarding state.
	if _, err := dockerRoleArgs(dockerRoleOptions{role: "auditor", image: "sha256:" + strings.Repeat("0", 64), platform: "linux/amd64", work: d.Work, trust: d.Trust, keys: d.Keys}, []string{"mpc-ceremony", "version"}, os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	st, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		return errors.New("role preparation requires an interactive terminal")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	prep := filepath.Join(d.Work, "role-preparation")
	for _, dir := range []string{prep, filepath.Join(d.Work, "ceremony"), filepath.Join(d.Work, "ceremony/public"), filepath.Join(d.Work, "ceremony/config")} {
		if err := ensurePrivateDirectory(dir); err != nil {
			return err
		}
	}
	path := filepath.Join(prep, "draft.json")
	lock, err := acquireParticipantRunLock(path, prep)
	if err != nil {
		return err
	}
	defer lock.release()
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return errors.New("preparation state must be a private regular file")
		}
		var saved rolePreparation
		if err := setupReadJSON(path, &saved); err != nil {
			return err
		}
		if saved.Schema != d.Schema || saved.Name != d.Name || saved.Role != d.Role || saved.Release != d.Release || saved.Work != d.Work || saved.Trust != d.Trust || saved.Keys != d.Keys || saved.Values == nil {
			return errors.New("saved preparation differs; use its original release, role and folders")
		}
		d = saved
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	p := rolePreparer{d: d, path: path, settingsRoot: root, ui: coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}, run: executeGuidedChild}
	if err := p.save(); err != nil {
		return err
	}
	return p.menu()
}
