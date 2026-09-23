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
	CPUs        int `json:"cpus"`
	MemoryGiB   int `json:"memory_gib"`
	GoMemoryGiB int `json:"go_memory_gib"`
	GoGCPercent int `json:"go_gc_percent"`
}

var proofDockerRuntimeLimits = dockerRuntimeLimits{
	CPUs: defaultDockerRuntimeCPUs, MemoryGiB: defaultDockerRuntimeMemoryGiB,
	GoMemoryGiB: defaultDockerRuntimeGoMemoryGiB, GoGCPercent: defaultDockerRuntimeGoGCPercent,
}

// resolvedDockerRuntimeLimits retains the released allocation for records that
// predate configurable resources. Present but invalid records never fall back.
func resolvedDockerRuntimeLimits(saved *dockerRuntimeLimits) (dockerRuntimeLimits, error) {
	limits := dockerRuntimeLimits{CPUs: 2, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	if saved != nil {
		limits = *saved
	}
	if err := limits.validate(); err != nil {
		return dockerRuntimeLimits{}, err
	}
	return limits, nil
}

func (l dockerRuntimeLimits) validate() error {
	if l.CPUs < 1 || l.CPUs > 1024 {
		return fmt.Errorf("CPU allocation must be between 1 and 1024")
	}
	if l.MemoryGiB < 3 || l.MemoryGiB > 65536 {
		return fmt.Errorf("container memory must be between 3 and 65536 GiB")
	}
	if l.GoMemoryGiB < 1 || l.GoMemoryGiB > l.MemoryGiB-2 {
		return fmt.Errorf("Go memory target must leave at least 2 GiB below the container limit")
	}
	if l.GoGCPercent < 1 || l.GoGCPercent > 1000 {
		return fmt.Errorf("Go GC percentage must be between 1 and 1000")
	}
	return nil
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

func (l dockerRuntimeLimits) roleFlags() []string {
	return []string{"--cpus", strconv.Itoa(l.CPUs), "--memory-gib", strconv.Itoa(l.MemoryGiB), "--go-memory-gib", strconv.Itoa(l.GoMemoryGiB), "--go-gc-percent", strconv.Itoa(l.GoGCPercent)}
}

// matchesSecurityFacts binds retained inspection evidence to this operation's
// allocation, rather than to the preferences selected for a later operation.
func (l dockerRuntimeLimits) matchesSecurityFacts(f dockerSecurityFacts) bool {
	memory := int64(l.MemoryGiB) << 30
	return l.validate() == nil && f.RuntimeLimitsVerified &&
		f.CPULimitNano == int64(l.CPUs)*1_000_000_000 &&
		f.MemoryLimitBytes == memory && f.MemorySwapLimitBytes == memory &&
		f.GoMaxProcs == strconv.Itoa(l.CPUs) &&
		f.GoMemoryLimit == strconv.Itoa(l.GoMemoryGiB)+"GiB" &&
		f.GoGCPercent == strconv.Itoa(l.GoGCPercent)
}

func (l dockerRuntimeLimits) announceStart() {
	fmt.Fprintf(os.Stderr, "Starting operation with %d CPUs and %d GiB memory. Updated preferences apply to later operations.\n", l.CPUs, l.MemoryGiB)
}
