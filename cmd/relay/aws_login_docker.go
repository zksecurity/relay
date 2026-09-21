package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const awsLoginRuntimeConfig = "[profile relay-coordinator]\ncredential_process = /usr/local/bin/relay aws-login-credentials /credentials/aws-login/current.json\n"
const awsLoginOwnerLabel = "org.zksecurity.relay.aws-login"

func awsCredentialCommand(o dockerRoleOptions, command []string) bool {
	return o.role == "coordinator" && len(command) > 0 && (command[0] == "aws" || len(command) >= 3 && command[0] == "relay" && command[1] == "coordinator")
}

// This runtime owns exactly one named container. The login cache and binding
// remain on the host; only short-lived verified exports enter the container.
func runAWSLoginDocker(o dockerRoleOptions, command []string, b awsLoginBinding, binary, endpoint string) (result error) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	return runAWSLoginDockerContext(ctx, o, command, b, binary, endpoint)
}

func runAWSLoginDockerContext(ctx context.Context, o dockerRoleOptions, command []string, b awsLoginBinding, binary, endpoint string) (result error) {
	docker := func(ctx context.Context, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, binary, append([]string{"--host", endpoint}, args...)...)
		cmd.Env = dockerEnvironmentWithoutTargetOverrides()
		cmd.WaitDelay = time.Second
		var out awsSetupBuffer
		cmd.Stdout = &out
		err := cmd.Run()
		return strings.TrimSpace(out.data.String()), err
	}
	// Probe without any role mounts or credentials. Old frozen images cannot run
	// the provider; fail before creating the actual action container.
	probeCtx, probeCancel := context.WithTimeout(ctx, 30*time.Second)
	probe, err := docker(probeCtx, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--platform", o.platform, "--entrypoint=/usr/local/bin/relay", o.image, "aws-login-credentials", "--probe")
	probeCancel()
	if err != nil || probe != awsLoginSchema {
		return errors.New("this role image does not support renewable AWS logins; use a compatible release for a new ceremony, or retain the frozen release and use its existing credential workflow")
	}
	credentials, err := refreshAWSLogin(ctx, b)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "relay-aws-login-")
	if err != nil {
		return err
	}
	retain := false
	defer func() {
		if !retain {
			_ = os.RemoveAll(dir)
		} else {
			fmt.Fprintf(os.Stderr, "AWS runtime retained at %s; confirm the action container is removed before deleting this directory.\n", dir)
		}
	}()
	if err = os.WriteFile(filepath.Join(dir, "config"), []byte(awsLoginRuntimeConfig+"region = "+b.Region+"\n"), 0600); err != nil {
		return err
	}
	path := filepath.Join(dir, "current.json")
	if err = saveJSONAtomic(path, credentials); err != nil {
		return err
	}
	o.credentials = ""
	o.awsLoginRuntime = dir
	argv, err := dockerRoleArgs(o, command, os.Getuid(), os.Getgid())
	if err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	name := "relay-aws-login-" + hex.EncodeToString(random)
	// Explicit create/start lets cancellation clean up a known container, even
	// when the attached client exits before the workload does.
	createArgs := []string{"create", "--name", name, "--label", awsLoginOwnerLabel + "=" + name}
	for _, arg := range argv[1:] {
		if arg != "--rm" {
			createArgs = append(createArgs, arg)
		}
	}
	created := false
	var containerID string
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		owner, e := docker(cleanupCtx, "inspect", "--format", "{{.Id}} {{ index .Config.Labels \""+awsLoginOwnerLabel+"\" }}", name)
		fields := strings.Fields(owner)
		if e == nil && len(fields) == 2 && fields[1] == name && (!created || fields[0] == containerID) {
			decoded, decodeErr := hex.DecodeString(fields[0])
			if decodeErr != nil || len(decoded) != 32 {
				retain = true
				result = errors.Join(result, errors.New("Docker returned an invalid cleanup container ID"))
				return
			}
			_, _ = docker(cleanupCtx, "stop", "--time", "10", fields[0])
			_, e = docker(cleanupCtx, "rm", "--force", fields[0])
			if e == nil {
				return
			}
		}
		// After a confirmed successful create, a missing container is acceptable
		// only when a successful daemon listing confirms absence.
		if created {
			ids, listErr := docker(cleanupCtx, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
			if listErr == nil && ids == "" {
				return
			}
		}
		retain = true
		result = errors.Join(result, fmt.Errorf("could not confirm cleanup of owned container %s", name))
	}()
	createCtx, createCancel := context.WithTimeout(ctx, time.Minute)
	id, err := docker(createCtx, createArgs...)
	createCancel()
	if err != nil {
		return errors.New("AWS action container creation failed or was interrupted")
	}
	if decoded, decodeErr := hex.DecodeString(id); decodeErr != nil || len(decoded) != 32 {
		return errors.New("Docker returned an invalid action container ID")
	}
	created = true
	containerID = id
	runtimeCtx, runtimeCancel := context.WithCancel(ctx)
	defer runtimeCancel()
	renewal := make(chan error, 1)
	go func() { renewal <- maintainAWSLogin(runtimeCtx, b, path, credentials, refreshAWSLogin) }()
	cmd := exec.CommandContext(runtimeCtx, binary, "--host", endpoint, "start", "--attach", "--interactive", id)
	cmd.Env = dockerEnvironmentWithoutTargetOverrides()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = time.Second
	finished := make(chan error, 1)
	go func() { finished <- cmd.Run() }()
	select {
	case err = <-finished:
		runtimeCancel()
		<-renewal
		return err
	case err = <-renewal:
		runtimeCancel()
		<-finished
		return err
	}
}
