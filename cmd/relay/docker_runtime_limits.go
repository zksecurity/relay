package main

import (
	"fmt"
	"os"
	"strconv"
)

const (
	defaultDockerRuntimeCPUs        = 2
	defaultDockerRuntimeMemoryGiB   = 6
	defaultDockerRuntimeGoMemoryGiB = 4
	defaultDockerRuntimeGoGCPercent = 25
)

// dockerRuntimeLimits bound proof work independently of the role or command
// that reaches the pinned image. The Go heap target deliberately leaves room
// below the container limit for mmap-backed proof data and non-Go processes.
type dockerRuntimeLimits struct {
	CPUs        int
	MemoryGiB   int
	GoMemoryGiB int
	GoGCPercent int
}

var proofDockerRuntimeLimits = dockerRuntimeLimits{
	CPUs: defaultDockerRuntimeCPUs, MemoryGiB: defaultDockerRuntimeMemoryGiB,
	GoMemoryGiB: defaultDockerRuntimeGoMemoryGiB, GoGCPercent: defaultDockerRuntimeGoGCPercent,
}

func (l dockerRuntimeLimits) dockerArgs() []string {
	memory := strconv.Itoa(l.MemoryGiB) + "g"
	return []string{
		"--cpus", strconv.Itoa(l.CPUs),
		"--memory", memory,
		"--memory-swap", memory,
		"--env", "GOMAXPROCS=" + strconv.Itoa(l.CPUs),
		"--env", "GOMEMLIMIT=" + strconv.Itoa(l.GoMemoryGiB) + "GiB",
		"--env", "GOGC=" + strconv.Itoa(l.GoGCPercent),
	}
}

func dockerRuntimeArgs() []string {
	return proofDockerRuntimeLimits.dockerArgs()
}

func dockerProofInspectionArgs(directory, image, platform string, commandArgs []string) []string {
	argv := []string{
		"run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--platform", platform,
		"--mount", "type=bind,src=" + directory + ",dst=/input,readonly",
		"--entrypoint", "/usr/local/bin/mpc-ceremony",
	}
	argv = append(argv, dockerRuntimeArgs()...)
	argv = append(argv, image)
	return append(argv, commandArgs...)
}
