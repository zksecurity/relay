package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// The approved proof-tool release contains Linux binaries. On macOS, run the
// unchanged Linux verifier and its pinned proof tool in the same attested role
// image as the installed launcher. No ceremony workspace or signing key enters
// the container.
func runMacVerifyCeremony(archive, publishedBaseURL, expectedID, expectedKey string, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("--max-expanded-bytes must be positive")
	}
	archivePath, err := macVerifierRegularPath(archive)
	if err != nil {
		return fmt.Errorf("public archive: %w", err)
	}
	keyPath := ""
	if expectedKey != "" {
		keyPath, err = macVerifierRegularPath(expectedKey)
		if err != nil {
			return fmt.Errorf("trusted coordinator key: %w", err)
		}
	}
	if err := macVerifierLocalDocker(); err != nil {
		return err
	}
	platform := "linux/" + runtime.GOARCH
	image, _, err := verifiedReleaseImage("role-images-"+launcherCommit(), "coordinator", platform)
	if err != nil {
		return fmt.Errorf("authenticate verifier image: %w", err)
	}
	scratch, err := os.MkdirTemp("", "relay-public-verifier-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	args := macVerifierDockerArgs(platform, image, archivePath, keyPath, scratch, publishedBaseURL, expectedID, maxBytes)
	cidFile := filepath.Join(scratch, "container-id")
	args = append([]string{args[0], "--cidfile", cidFile}, args[1:]...)
	defer func() {
		if raw, err := os.ReadFile(cidFile); err == nil {
			id := strings.TrimSpace(string(raw))
			if len(id) == 64 && sha256HexPattern.MatchString(id) {
				_ = exec.Command("docker", "rm", "--force", id).Run()
			}
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Docker public verification: %w", err)
	}
	return nil
}

func macVerifierRegularPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("must be a regular file, not a symlink")
	}
	return absolute, nil
}

func macVerifierLocalDocker() error {
	if host := os.Getenv("DOCKER_HOST"); host != "" && !strings.HasPrefix(host, "unix://") {
		return errors.New("public verification requires a local Docker daemon")
	}
	cmd := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("inspect local Docker context: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "unix://") {
		return errors.New("public verification requires a local Unix-socket Docker context")
	}
	return nil
}

func macVerifierDockerArgs(platform, image, archive, key, scratch, publishedBaseURL, expectedID string, maxBytes int64) []string {
	args := []string{"run", "--rm", "--platform", platform, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()), "--env", "TMPDIR=/scratch", "--mount", "type=bind,source=" + scratch + ",target=/scratch", "--mount", "type=bind,source=" + archive + ",target=/work/archive.zip,readonly"}
	if publishedBaseURL == "" {
		args = append(args, "--network", "none")
	}
	if key != "" {
		args = append(args, "--mount", "type=bind,source="+key+",target=/work/coordinator-key.hex,readonly")
	}
	args = append(args, image, "verify-ceremony", "--archive", "/work/archive.zip", "--max-expanded-bytes", strconv.FormatInt(maxBytes, 10), "--mpc-ceremony", "/usr/local/bin/mpc-ceremony")
	if publishedBaseURL != "" {
		args = append(args, "--published-base-url", publishedBaseURL, "--expected-ceremony-id", expectedID, "--expected-coordinator-public-key-file", "/work/coordinator-key.hex")
	}
	return args
}
