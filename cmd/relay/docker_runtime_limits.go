package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	dockerRuntimeCPUsEnvironment       = "RELAY_DOCKER_RUNTIME_CPUS"
	dockerRuntimeMemoryEnvironment     = "RELAY_DOCKER_RUNTIME_MEMORY_GIB"
	dockerRuntimeGoMemoryEnvironment   = "RELAY_DOCKER_RUNTIME_GO_MEMORY_GIB"
	dockerRuntimeGoGCEnvironment       = "RELAY_DOCKER_RUNTIME_GOGC"
	defaultDockerRuntimeCPUs           = 2
	defaultDockerRuntimeMemoryGiB      = 6
	defaultDockerRuntimeGoMemoryGiB    = 4
	defaultDockerRuntimeGoGCPercent    = 25
	minimumDockerRuntimeMemoryGiB      = 4
	minimumDockerRuntimeMemoryHeadroom = 2
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

func loadDockerRuntimeLimits() (dockerRuntimeLimits, error) {
	limits := dockerRuntimeLimits{
		CPUs: defaultDockerRuntimeCPUs, MemoryGiB: defaultDockerRuntimeMemoryGiB,
		GoMemoryGiB: defaultDockerRuntimeGoMemoryGiB, GoGCPercent: defaultDockerRuntimeGoGCPercent,
	}
	values := []struct {
		name        string
		destination *int
		minimum     int
		maximum     int
	}{
		{dockerRuntimeCPUsEnvironment, &limits.CPUs, 1, 64},
		{dockerRuntimeMemoryEnvironment, &limits.MemoryGiB, minimumDockerRuntimeMemoryGiB, 1024},
		{dockerRuntimeGoMemoryEnvironment, &limits.GoMemoryGiB, 1, 1023},
		{dockerRuntimeGoGCEnvironment, &limits.GoGCPercent, 10, 500},
	}
	for _, value := range values {
		raw := strings.TrimSpace(os.Getenv(value.name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < value.minimum || parsed > value.maximum {
			return dockerRuntimeLimits{}, fmt.Errorf("%s must be an integer from %d through %d", value.name, value.minimum, value.maximum)
		}
		*value.destination = parsed
	}
	if limits.GoMemoryGiB+minimumDockerRuntimeMemoryHeadroom > limits.MemoryGiB {
		return dockerRuntimeLimits{}, fmt.Errorf("%s must leave at least %d GiB below %s", dockerRuntimeGoMemoryEnvironment, minimumDockerRuntimeMemoryHeadroom, dockerRuntimeMemoryEnvironment)
	}
	return limits, nil
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

func dockerRuntimeArgs() ([]string, error) {
	limits, err := loadDockerRuntimeLimits()
	if err != nil {
		return nil, err
	}
	return limits.dockerArgs(), nil
}

func dockerProofInspectionArgs(directory, image, platform string, commandArgs []string) ([]string, error) {
	runtimeArgs, err := dockerRuntimeArgs()
	if err != nil {
		return nil, err
	}
	argv := []string{
		"run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--platform", platform,
		"--mount", "type=bind,src=" + directory + ",dst=/input,readonly",
		"--entrypoint", "/usr/local/bin/mpc-ceremony",
	}
	argv = append(argv, runtimeArgs...)
	argv = append(argv, image)
	return append(argv, commandArgs...), nil
}
