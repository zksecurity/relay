package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// This launcher packages ordinary role tools, not the toxic-waste lifecycle.
// Participants use the existing host supervisor and its separate Docker driver.
type dockerRoleOptions struct {
	role, image, platform, work, trust, keys, credentials, config, docker string
	r2Parent, r2Control                                                   string
}

var roleImagePattern = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|[^\s@]+@sha256:[0-9a-f]{64})$`)

func runDockerRole(args []string) error {
	var o dockerRoleOptions
	set := flag.NewFlagSet("role", flag.ContinueOnError)
	set.StringVar(&o.role, "role", "", "coordinator, participant, witness, mirror, auditor, upload-station, release-signer, decision-signer, or keygen")
	set.StringVar(&o.image, "image", "", "preloaded approved image digest or immutable image ID")
	set.StringVar(&o.platform, "platform", "linux/amd64", "linux/amd64 or linux/arm64")
	set.StringVar(&o.work, "work", "", "dedicated writable role directory, mounted at /work")
	set.StringVar(&o.trust, "trust", "", "public trust directory, mounted read-only at /trust")
	set.StringVar(&o.keys, "keys", "", "dedicated role key directory, mounted read-only at /keys")
	set.StringVar(&o.credentials, "aws-credentials", "", "coordinator-only AWS credentials file, mounted read-only")
	set.StringVar(&o.r2Parent, "r2-parent-credential", "", "protected R2 inbox parent secret file; mounted only for grant issuance")
	set.StringVar(&o.r2Control, "r2-control-credential", "", "protected R2 control token file; mounted only for storage checks")
	set.StringVar(&o.config, "config", "", "participant Docker profile on the host")
	set.StringVar(&o.docker, "docker-cli", "docker", "Docker CLI path")
	if err := set.Parse(args); err != nil {
		return err
	}
	if o.role == "participant" {
		var invalid string
		set.Visit(func(f *flag.Flag) {
			if f.Name != "role" && f.Name != "config" {
				invalid = f.Name
			}
		})
		if invalid != "" {
			return fmt.Errorf("participant option --%s belongs in its Docker profile, not the launcher", invalid)
		}
		return runDockerRoleParticipant(o, set.Args())
	}
	argv, err := dockerRoleArgs(o, set.Args(), os.Getuid(), os.Getgid())
	if err != nil {
		return err
	}
	client := osDockerCommandClient{binary: o.docker}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return err
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return err
	}
	binary, err := exec.LookPath(o.docker)
	if err != nil {
		return err
	}
	// Replace the launcher so Docker receives terminal and service signals.
	return syscall.Exec(binary, append([]string{binary, "--host", endpoint}, argv...), dockerEnvironmentWithoutTargetOverrides())
}

func runDockerRoleParticipant(o dockerRoleOptions, args []string) error {
	if o.config == "" || o.image != "" || o.work != "" || o.trust != "" || o.keys != "" || o.credentials != "" {
		return errors.New("participant requires --config only; image, mounts, and platform belong in its Docker profile")
	}
	if len(args) == 0 || (args[0] != "run" && args[0] != "status") {
		return errors.New("participant command must be run, status")
	}
	for _, arg := range args[1:] {
		if arg == "--config" || arg == "-config" || strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			return errors.New("supply participant --config before the command separator only")
		}
	}
	profile, err := loadRoleConfig(o.config, "participant")
	if err != nil {
		return err
	}
	if profile.ExecutionMode != dockerExecutionMode {
		return errors.New("role launcher requires a Docker participant profile; native execution is not supported here")
	}
	return runParticipant(append([]string{args[0], "--config", o.config}, args[1:]...))
}

func dockerRoleArgs(o dockerRoleOptions, command []string, uid, gid int) ([]string, error) {
	if (o.r2Parent != "" || o.r2Control != "") && o.role != "coordinator" {
		return nil, errors.New("R2 administrative credentials are coordinator-only")
	}
	// A saved profile may support multiple tasks. Do not expose its credentials
	// to proof computation, identity generation, or unrelated online commands.
	parentTask, controlTask := false, false
	if len(command) >= 3 && command[0] == "relay" && command[1] == "coordinator" {
		parentTask = command[2] == "grant" || command[2] == "evidence-grant" || command[2] == "check-storage" || command[2] == "configure-storage"
		controlTask = command[2] == "configure-storage" || command[2] == "check-storage"
	}
	if !parentTask {
		o.r2Parent = ""
	}
	if !controlTask {
		o.r2Control = ""
	}
	offline := false
	switch o.role {
	case "coordinator", "witness", "mirror", "auditor", "upload-station":
	case "release-signer", "decision-signer", "keygen":
		offline = true
	default:
		return nil, errors.New("unknown role")
	}
	if o.config != "" {
		return nil, errors.New("--config is participant-only; pass other tool flags after --")
	}
	if !roleImagePattern.MatchString(o.image) || strings.HasPrefix(o.image, "-") {
		return nil, errors.New("--image must be an approved immutable image digest or ID")
	}
	if o.platform != "linux/amd64" && o.platform != "linux/arm64" {
		return nil, errors.New("unsupported Linux platform")
	}
	if uid <= 0 || gid < 0 {
		return nil, errors.New("run the launcher as a non-root operator")
	}
	if len(command) == 0 || (command[0] != "relay" && command[0] != "mpc-ceremony" && !(command[0] == "aws" && o.role == "coordinator")) {
		return nil, errors.New("command must start with relay or mpc-ceremony (coordinators may also run aws)")
	}
	if offline && command[0] != "mpc-ceremony" {
		return nil, errors.New("offline roles run mpc-ceremony only; use a separate upload station for Relay")
	}
	if o.role == "keygen" && (len(command) < 3 || command[1] != "identity" || command[2] != "generate") {
		return nil, errors.New("keygen requires mpc-ceremony identity generate")
	}
	if command[0] == "relay" && len(command) > 1 {
		if command[1] == "participate" || command[1] == "participant" || command[1] == "role" {
			return nil, errors.New("participant operations must use the host participant supervisor")
		}
	}
	if command[0] == "mpc-ceremony" {
		for i := 1; i+1 < len(command); i++ {
			if (command[i] == "phase1" || command[i] == "phase2") && command[i+1] == "contribute" {
				return nil, errors.New("contributions must use the host participant supervisor")
			}
		}
	}
	if o.credentials != "" && o.role != "coordinator" {
		return nil, errors.New("only coordinators may mount AWS credentials; other online roles use scoped grant files")
	}
	if command[0] != "aws" && !(len(command) >= 3 && command[0] == "relay" && command[1] == "coordinator") {
		o.credentials = ""
	}
	if o.keys != "" && o.role == "upload-station" {
		return nil, errors.New("upload stations must not receive signing keys")
	}
	var sources []string
	for _, source := range []string{o.work, o.trust, o.keys, o.credentials, o.r2Parent, o.r2Control} {
		if source == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			return nil, err
		}
		for _, previous := range sources {
			if resolved == previous || strings.HasPrefix(resolved, previous+"/") || strings.HasPrefix(previous, resolved+"/") {
				return nil, errors.New("work, trust, keys, and credentials mounts must not overlap")
			}
		}
		sources = append(sources, resolved)
	}
	argv := []string{"run", "--rm", "--pull=never", "--interactive", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit=core=0:0", "--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid), "--platform", o.platform, "--workdir=/work", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777", "--env=HOME=/tmp", "--env=AWS_EC2_METADATA_DISABLED=true", "--env=AWS_PAGER=", "--env=AWS_CONFIG_FILE=/nonexistent", "--env=AWS_SHARED_CREDENTIALS_FILE=/nonexistent", "--label=org.zksecurity.relay.role=" + o.role}
	if offline {
		argv = append(argv, "--network=none")
	} else {
		argv = append(argv, "--network=bridge")
	}
	for _, mount := range []struct {
		source, target string
		readonly, file bool
	}{
		{o.work, "/work", false, false}, {o.trust, "/trust", true, false}, {o.keys, "/keys", true, false}, {o.credentials, "/credentials/aws", true, true},
		{o.r2Parent, "/credentials/r2-parent", true, true}, {o.r2Control, "/credentials/r2-control", true, true},
	} {
		if mount.source == "" && mount.target != "/work" {
			continue
		}
		if err := validateRoleMount(mount.source, mount.file); err != nil {
			return nil, fmt.Errorf("%s mount: %w", mount.target, err)
		}
		value := "type=bind,src=" + mount.source + ",dst=" + mount.target
		if mount.readonly {
			value += ",readonly"
		}
		argv = append(argv, "--mount", value)
	}
	if o.credentials != "" {
		argv = append(argv, "--env=AWS_SHARED_CREDENTIALS_FILE=/credentials/aws")
	}
	if o.r2Parent != "" {
		argv = append(argv, "--env="+r2ParentSecretEnvironment+"_FILE=/credentials/r2-parent")
	}
	if o.r2Control != "" {
		argv = append(argv, "--env="+r2ControlTokenEnvironment+"_FILE=/credentials/r2-control")
	}
	argv = append(argv, "--entrypoint=/usr/local/bin/"+command[0], o.image)
	return append(argv, command[1:]...), nil
}

func validateRoleMount(name string, file bool) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || strings.ContainsAny(name, ",\n\r") {
		return errors.New("use an absolute clean path without commas or newlines")
	}
	home, _ := os.UserHomeDir()
	for _, broad := range []string{"/", "/Users", "/home", "/tmp", "/private/tmp", "/var", "/etc", "/run", "/var/run", home} {
		if name == broad {
			return errors.New("use a dedicated role directory, not a broad system/home directory")
		}
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if file {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("credentials must be a regular mode-0600 (or stricter) file")
		}
		return nil
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("role directories must be real, private directories (mode 0700)")
	}
	// Never expose a Docker socket or another host service through these mounts.
	return filepath.WalkDir(name, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return errors.New("role directories may contain only regular files and directories, no symlinks or sockets")
		}
		return nil
	})
}
