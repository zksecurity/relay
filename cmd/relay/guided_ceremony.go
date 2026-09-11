package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const guidedSchema = "relay-guided-role-v1"

var guidedName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Saved commands contain public identifiers and file paths, not file contents.
// They are operator-selected actions, never inferred from untrusted web status.
type guidedProfile struct {
	ReleaseCommit string   `json:"release_commit,omitempty"`
	Schema        string   `json:"schema"`
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Image         string   `json:"image,omitempty"`
	Platform      string   `json:"platform,omitempty"`
	Work          string   `json:"work,omitempty"`
	Trust         string   `json:"trust,omitempty"`
	Keys          string   `json:"keys,omitempty"`
	Credentials   string   `json:"aws_credentials,omitempty"`
	Config        string   `json:"participant_config,omitempty"`
	Command       []string `json:"command,omitempty"`
	R2Parent      string   `json:"r2_parent_credential,omitempty"`
	R2Control     string   `json:"r2_control_credential,omitempty"`
}

func (p guidedProfile) options() dockerRoleOptions {
	return dockerRoleOptions{role: p.Role, image: p.Image, platform: p.Platform, work: p.Work, trust: p.Trust, keys: p.Keys, credentials: p.Credentials, config: p.Config, docker: "docker", r2Parent: p.R2Parent, r2Control: p.R2Control}
}

func guidedRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "relay", "ceremonies"), nil
}

func guidedDirectory(root, name, role string) (string, error) {
	if !guidedName.MatchString(name) || !guidedName.MatchString(role) {
		return "", errors.New("ceremony name and role must be short lowercase names, not paths")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("--settings-root must be an absolute clean path")
	}
	return filepath.Join(root, name, role), nil
}

func machineDockerPlatform() (string, error) {
	if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", errors.New("guided setup supports Linux and macOS on AMD64 or ARM64")
	}
	return "linux/" + runtime.GOARCH, nil
}

func runGuidedSetup(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony setup NAME --role ROLE [settings] -- TOOL ARGS...")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	p := guidedProfile{Schema: guidedSchema, Name: args[0]}
	var amd64Image, arm64Image, releaseTag string
	var pull bool
	set := flag.NewFlagSet("ceremony setup", flag.ContinueOnError)
	set.StringVar(&root, "settings-root", root, "private saved-settings directory")
	set.StringVar(&p.Role, "role", "", "ceremony role")
	set.StringVar(&releaseTag, "release", "", "verify release map and automatically select the role image")
	set.StringVar(&p.Image, "image", "", "approved image digest for this machine")
	set.StringVar(&amd64Image, "image-amd64", "", "approved Linux AMD64 image digest")
	set.StringVar(&arm64Image, "image-arm64", "", "approved Linux ARM64 image digest")
	set.StringVar(&p.Work, "work", "", "dedicated role work directory; created automatically if omitted")
	set.StringVar(&p.Trust, "trust", "", "dedicated public trust directory; created automatically if omitted")
	set.StringVar(&p.Keys, "keys", "", "existing protected role key directory (never created or populated automatically)")
	set.StringVar(&p.Credentials, "aws-credentials", "", "coordinator-only credentials file")
	set.StringVar(&p.R2Parent, "r2-parent-credential", "", "protected R2 inbox parent secret file")
	set.StringVar(&p.R2Control, "r2-control-credential", "", "protected R2 control token file")
	set.StringVar(&p.Config, "config", "", "existing participant Docker profile")
	set.BoolVar(&pull, "download", true, "download the approved digest during setup if absent; use --download=false for offline setup")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if (p.R2Parent != "" || p.R2Control != "") && p.Role != "coordinator" {
		return errors.New("R2 administrative credentials are coordinator-only")
	}
	var releaseImage string
	if releaseTag != "" {
		if !pull || p.Image != "" || amd64Image != "" || arm64Image != "" {
			return errors.New("--release requires online verification; do not combine it with image overrides or --download=false")
		}
		platform, err := machineDockerPlatform()
		if err != nil {
			return err
		}
		releaseImage, p.ReleaseCommit, err = verifiedReleaseImage(releaseTag, p.Role, platform)
		if err != nil {
			return err
		}
		if p.Role != "participant" {
			p.Image = releaseImage
		}
	}
	dir, err := guidedDirectory(root, p.Name, p.Role)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("saved profile already exists or cannot be inspected; use a new name instead of overwriting it")
	}
	if p.Role == "participant" {
		if len(set.Args()) != 0 || p.Config == "" || p.Image != "" || amd64Image != "" || arm64Image != "" || p.Credentials != "" {
			return errors.New("participant setup takes --config and optional --work/--trust/--keys; execution settings come from that authenticated Docker profile")
		}
		if (p.Work != "" || p.Trust != "" || p.Keys != "") && (p.Work == "" || p.Trust == "" || p.Keys == "") {
			return errors.New("participant custody settings require all of --work, --trust and --keys")
		}
		config, err := loadRoleConfig(p.Config, "participant")
		if err != nil {
			return err
		}
		if config.ExecutionMode != dockerExecutionMode {
			return errors.New("guided participants require a Docker profile")
		}
		if releaseImage != "" && (config.DockerImage != releaseImage || config.DockerPlatform != "linux/"+runtime.GOARCH) {
			return errors.New("participant profile does not match the verified release image and platform")
		}
		p.Config, err = filepath.Abs(p.Config)
		if err != nil {
			return err
		}
		if err := prepareGuidedImage(config.DockerImage, config.DockerPlatform, config.DockerCLI, pull); err != nil {
			return err
		}
	} else {
		p.Platform, err = machineDockerPlatform()
		if err != nil {
			return err
		}
		if p.Image != "" && (amd64Image != "" || arm64Image != "") {
			return errors.New("use --image or the platform image map, not both")
		}
		if p.Image == "" {
			p.Image = amd64Image
			if p.Platform == "linux/arm64" {
				p.Image = arm64Image
			}
		}
		if !roleImagePattern.MatchString(p.Image) {
			return fmt.Errorf("no approved immutable image supplied for %s", p.Platform)
		}
		p.Command = append([]string(nil), set.Args()...)
		if err := checkSavedCommand(p.Command); err != nil {
			return err
		}
		for _, target := range []*string{&p.Work, &p.Trust} {
			if *target == "" {
				name := "work"
				if target == &p.Trust {
					name = "trust"
				}
				*target = filepath.Join(dir, name)
				if err := ensurePrivateDirectory(*target); err != nil {
					return err
				}
			}
		}
		validationCommand := p.Command
		if len(validationCommand) == 0 {
			validationCommand = []string{"mpc-ceremony", "identity", "generate"}
		}
		if _, err := dockerRoleArgs(p.options(), validationCommand, os.Getuid(), os.Getgid()); err != nil {
			return err
		}
		if err := prepareGuidedImage(p.Image, p.Platform, "docker", pull); err != nil {
			return err
		}
	}
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), p, 0o600); err != nil {
		return err
	}
	fmt.Printf("Setup ready for %s / %s. Configured image is available.\nSaved settings: %s\n", p.Name, p.Role, dir)
	if len(p.Command) == 0 && len(roleFlowStages(p.Role)) > 0 {
		fmt.Printf("Guided workflow: relay ceremony guide %s --role %s --settings-root %q\n", p.Name, p.Role, root)
	} else {
		fmt.Printf("Open with: relay ceremony open %s --role %s --settings-root %q\n", p.Name, p.Role, root)
	}
	if p.Role != "participant" && len(p.Command) == 0 {
		fmt.Println("For manual actions instead, use ceremony open with --action NAME -- TOOL ARGS...")
	}
	return nil
}

func checkSavedCommand(command []string) error {
	// Never save credential-setting commands or common inline-secret flags.
	for _, arg := range command {
		lower := strings.ToLower(arg)
		for _, word := range []string{"secret-access-key", "session-token", "password", "private-key-hex", "private-key="} {
			if strings.Contains(lower, word) {
				return errors.New("saved commands must reference protected files, not inline secrets")
			}
		}
	}
	if len(command) > 1 && command[0] == "aws" && command[1] == "configure" {
		return errors.New("do not save AWS credential configuration as a task")
	}
	return nil
}

func prepareGuidedImage(image, platform, docker string, pull bool) error {
	if docker == "" {
		docker = "docker"
	}
	return prepareGuidedImageWithClient(osDockerCommandClient{binary: docker}, image, platform, pull)
}

func prepareGuidedImageWithClient(client dockerCommandClient, image, platform string, pull bool) error {
	if !roleImagePattern.MatchString(image) {
		return errors.New("an approved immutable image is required")
	}
	if platform != "linux/amd64" && platform != "linux/arm64" {
		return errors.New("invalid approved image platform")
	}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return fmt.Errorf("Docker is unavailable: install/start Docker and retry setup: %w", err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return err
	}
	bound := client.BindHost(endpoint)
	if _, _, err := bound.Output("info", "--format", "{{.ID}}"); err != nil {
		return fmt.Errorf("Docker is not responding; start Docker and retry: %w", err)
	}
	inspect := func() ([]byte, error) {
		out, _, err := bound.Output("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image)
		return out, err
	}
	out, err := inspect()
	if err != nil && pull && strings.Contains(image, "@sha256:") {
		fmt.Printf("Downloading approved image for %s (no version selection): %s\n", platform, image)
		if err := bound.Attached(os.Stdout, os.Stderr, "pull", "--platform", platform, image); err != nil {
			return err
		}
		out, err = inspect()
	}
	if err != nil {
		return errors.New("approved image is not available; load it offline or rerun setup with --download and an approved repository digest")
	}
	if strings.TrimSpace(string(out)) != platform {
		return errors.New("image platform does not match the approved platform")
	}
	return nil
}

func readGuidedProfile(path, name, role string) (guidedProfile, error) {
	var p guidedProfile
	info, err := os.Lstat(path)
	if err != nil {
		return p, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return p, errors.New("saved profile must be a private, regular file under 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return p, errors.New("saved profile changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return p, errors.New("trailing data in saved profile")
	}
	if p.Schema != guidedSchema || p.Name != name || p.Role != role {
		return p, errors.New("saved profile does not match this ceremony alias and role")
	}
	return p, nil
}

// Read one byte at a time so confirmation does not consume input intended for
// the participant's later, separate erasure confirmation.
func confirmGuided(in io.Reader, out io.Writer) error {
	fmt.Fprint(out, "Continue? [y/N] ")
	var line []byte
	for len(line) < 16 {
		var b [1]byte
		n, err := in.Read(b[:])
		if err != nil {
			return errors.New("cancelled; no task was started")
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			if strings.ToLower(strings.TrimSpace(string(line))) == "y" {
				return nil
			}
			return errors.New("cancelled; no task was started")
		}
		line = append(line, b[0])
	}
	return errors.New("confirmation too long; no task was started")
}

type guidedAttempt struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	Success     bool   `json:"success"`
}

// Caller holds the shared profile lock. Action commands are immutable so retry
// history cannot accidentally refer to a different signing or upload operation.
func prepareGuidedAction(dir, action string, command []string) ([]string, string, error) {
	if !guidedName.MatchString(action) {
		return nil, "", errors.New("action must be a short lowercase name, not a path")
	}
	if err := checkSavedCommand(command); err != nil {
		return nil, "", err
	}
	if err := ensurePrivateDirectory(filepath.Join(dir, "actions")); err != nil {
		return nil, "", err
	}
	actionDir := filepath.Join(dir, "actions", action)
	if err := ensurePrivateDirectory(actionDir); err != nil {
		return nil, "", err
	}
	path := filepath.Join(actionDir, "profile.json")
	saved, err := readGuidedProfile(path, action, "action")
	if errors.Is(err, os.ErrNotExist) && len(command) != 0 {
		saved = guidedProfile{Schema: guidedSchema, Name: action, Role: "action", Command: command}
		err = writeJSONNoReplace(path, saved, 0o600)
	}
	if err != nil {
		return nil, "", fmt.Errorf("load action (new actions require a command after --): %w", err)
	}
	if len(saved.Command) == 0 {
		return nil, "", errors.New("saved action has no command")
	}
	if len(command) != 0 {
		if len(command) != len(saved.Command) {
			return nil, "", errors.New("action already names a different command; use a new action name")
		}
		for i := range command {
			if command[i] != saved.Command[i] {
				return nil, "", errors.New("action already names a different command; use a new action name")
			}
		}
	}
	activity := filepath.Join(actionDir, "activity")
	if err := ensurePrivateDirectory(activity); err != nil {
		return nil, "", err
	}
	return saved.Command, activity, nil
}

func runGuidedOpen(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony open NAME --role ROLE")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	var role, grant, resume, action string
	var status, retry, showCommand bool
	set := flag.NewFlagSet("ceremony open", flag.ContinueOnError)
	set.StringVar(&root, "settings-root", root, "saved-settings root")
	set.StringVar(&role, "role", "", "assigned role")
	set.StringVar(&action, "action", "", "named action using shared settings; supply its command after --")
	set.StringVar(&grant, "grant", "", "fresh participant grant file")
	set.StringVar(&resume, "resume-candidate", "", "public candidate to verify and resume, never recompute")
	set.BoolVar(&status, "status", false, "participant: verify/report public position without contributing")
	set.BoolVar(&retry, "reviewed-retry", false, "ordinary roles only: acknowledge manual review of outputs/state before retrying an interrupted task")
	set.BoolVar(&showCommand, "show-command", false, "also display the exact saved command for technical review")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if action == "" && len(set.Args()) != 0 {
		return errors.New("a command requires --action NAME")
	}
	if status && (grant != "" || resume != "") {
		return errors.New("--status cannot be combined with contribution or resume arguments")
	}
	dir, err := guidedDirectory(root, args[0], role)
	if err != nil {
		return err
	}
	p, err := readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], role)
	if err != nil {
		return err
	}
	if err := checkLauncherRelease(p.ReleaseCommit); err != nil {
		return err
	}
	lock, err := acquireParticipantRunLock(filepath.Join(dir, "profile.json"), filepath.Join(dir, "activity"))
	if err != nil {
		return err
	}
	defer lock.release()
	// Credential-reference refresh takes this same lock. Do not execute a
	// profile read just before a completed refresh.
	p, err = readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], role)
	if err != nil {
		return err
	}
	activity := filepath.Join(dir, "activity")
	if action != "" {
		if role == "participant" || len(p.Command) != 0 {
			return errors.New("--action requires shared non-participant settings saved without a command")
		}
		if grant != "" || resume != "" || status {
			return errors.New("--grant, --resume-candidate, and --status here are participant-only")
		}
		if len(set.Args()) != 0 {
			if _, err := dockerRoleArgs(p.options(), set.Args(), os.Getuid(), os.Getgid()); err != nil {
				return err
			}
		}
		p.Command, activity, err = prepareGuidedAction(dir, action, set.Args())
		if err != nil {
			return err
		}
	} else if role != "participant" && len(p.Command) == 0 {
		return errors.New("shared settings require --action NAME -- TOOL ARGS...; reuse the action name without a command to reopen it")
	}
	fmt.Printf("Ceremony alias: %s\nRole: %s\n", p.Name, p.Role)
	var launch []string
	if role == "participant" {
		if retry {
			return errors.New("participant recovery requires --resume-candidate or a status check, not --reviewed-retry")
		}
		config, err := loadRoleConfig(p.Config, "participant")
		if err != nil {
			return err
		}
		if config.ExecutionMode != dockerExecutionMode {
			return errors.New("participant profile is no longer Docker; stop and review setup")
		}
		if err := prepareGuidedImage(config.DockerImage, config.DockerPlatform, config.DockerCLI, false); err != nil {
			return err
		}
		fmt.Printf("Ceremony ID: %s\nIdentity: %s\nSigning-key file: %s\nPublic output: %s\n", config.CeremonyID, config.IdentityID, config.SigningKey, config.RunRoot)
		launch = []string{"role", "--role", "participant", "--config", p.Config, "--"}
		if status || (grant == "" && resume == "") {
			fmt.Println("Next action: verify current public position. This does not start a contribution.\nWhen it is your turn, reopen with --grant FILE.")
			launch = append(launch, "status")
		} else {
			if grant == "" {
				return errors.New("a fresh --grant FILE is required")
			}
			if resume == "" {
				if err := guardFreshGuidedContribution(filepath.Join(config.RunRoot, "candidates"), config.Phase, config.CeremonyID, config.IdentityID); err != nil {
					return err
				}
				fmt.Println("Next action: recheck your turn, contribute, verify cleanup, then request the separate erasure confirmation and upload.")
			} else {
				fmt.Printf("Next action: verify current state and resume public candidate %s. No new contribution will be generated.\n", resume)
			}
			launch = append(launch, "run", "--grant", grant)
			if resume != "" {
				launch = append(launch, "--resume-candidate", resume)
			}
		}
	} else {
		if grant != "" || resume != "" || status {
			return errors.New("--grant, --resume-candidate, and --status here are participant-only")
		}
		if _, err := dockerRoleArgs(p.options(), p.Command, os.Getuid(), os.Getgid()); err != nil {
			return err
		}
		if err := checkSavedCommand(p.Command); err != nil {
			return err
		}
		if err := prepareGuidedImage(p.Image, p.Platform, "docker", false); err != nil {
			return err
		}
		fmt.Printf("Key directory: %s\nWork/output directory: %s\n", p.Keys, p.Work)
		writeActionSummary(os.Stdout, p, p.Command)
		if showCommand {
			fmt.Printf("Exact command: %q\n", p.Command)
		}
		launch = []string{"role", "--role", p.Role, "--image", p.Image, "--platform", p.Platform, "--work", p.Work}
		for _, pair := range [][2]string{{"--trust", p.Trust}, {"--keys", p.Keys}, {"--aws-credentials", p.Credentials}, {"--r2-parent-credential", p.R2Parent}, {"--r2-control-credential", p.R2Control}} {
			if pair[1] != "" {
				launch = append(launch, pair[0], pair[1])
			}
		}
		launch = append(launch, "--")
		launch = append(launch, p.Command...)
	}
	if err := checkGuidedAttempts(activity); err != nil {
		if role == "participant" {
			fmt.Printf("Previous task needs attention: %v\nParticipant status/resume will recheck authenticated state.\n", err)
			if !status && grant != "" && resume == "" {
				return errors.New("check status or explicitly resume the saved public candidate; a new contribution is blocked")
			}
		} else if !retry {
			return fmt.Errorf("%w; review outputs and ceremony state before using --reviewed-retry; do not blindly rerun signing/upload tasks", err)
		}
	}
	fmt.Println("Docker: ready. Configured image is available. No image download will occur during this task.")
	if err := confirmGuided(os.Stdin, os.Stdout); err != nil {
		return err
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	record := filepath.Join(activity, fmt.Sprintf("attempt-%d.json", time.Now().UnixNano()))
	if err := writeJSONNoReplace(record, guidedAttempt{StartedAt: started}, 0o600); err != nil {
		return err
	}
	err = executeGuidedChild(launch)
	finishErr := writeJSONNoReplace(record+".done", guidedAttempt{StartedAt: started, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), Success: err == nil}, 0o600)
	if finishErr != nil {
		return fmt.Errorf("task returned %v but completion could not be recorded: %w", err, finishErr)
	}
	return err
}

func guardFreshGuidedContribution(parent, phase, ceremony, identity string) error {
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".relay-participant-run-") && strings.HasSuffix(entry.Name(), ".lock") {
			continue
		}
		// Retain completed candidates from the other phase. Unknown/partial
		// directories remain blocking; the actual run still authenticates state.
		if entry.IsDir() {
			manifestPath := filepath.Join(parent, entry.Name(), localCandidateManifestName)
			info, statErr := os.Lstat(manifestPath)
			if statErr == nil && info.Mode().IsRegular() && info.Size() < 1<<20 {
				raw, err := os.ReadFile(manifestPath)
				if err != nil {
					return err
				}
				manifest, decodeErr := access.Decode(raw, access.CandidateManifest.Validate)
				if decodeErr == nil && manifest.Phase != phase && manifest.CeremonyID == ceremony && manifest.ParticipantID == identity {
					continue
				}
			}
		}
		return fmt.Errorf("existing contribution/recovery data at %s; check status and use --resume-candidate for a completed candidate instead of starting a new contribution", filepath.Join(parent, entry.Name()))
	}
	return nil
}

func checkGuidedAttempts(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	// The latest invocation is the outstanding task. An explicit reviewed retry
	// that succeeds (or a participant status/resume) provides a new checkpoint;
	// previous records remain on disk for diagnosis.
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if !strings.HasPrefix(entry.Name(), "attempt-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()+".done"))
		if err != nil {
			return errors.New("an earlier task has no confirmed completion")
		}
		var done guidedAttempt
		if json.Unmarshal(raw, &done) != nil || !done.Success || done.CompletedAt == "" {
			return errors.New("an earlier task failed or its completion record is invalid")
		}
		return nil
	}
	return nil
}

func executeGuidedChild(args []string) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(binary, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		for {
			select {
			case s := <-signals:
				if s == syscall.SIGHUP {
					s = syscall.SIGTERM
				}
				_ = command.Process.Signal(s)
			case <-finished:
				return
			}
		}
	}()
	return command.Wait()
}
