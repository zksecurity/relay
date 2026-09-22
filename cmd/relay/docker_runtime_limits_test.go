package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestDockerRuntimeLimitsDefaults(t *testing.T) {
	limits := proofDockerRuntimeLimits
	want := dockerRuntimeLimits{CPUs: 2, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	if !reflect.DeepEqual(limits, want) {
		t.Fatalf("limits = %#v, want %#v", limits, want)
	}
	joined := strings.Join(limits.dockerArgs(), " ")
	for _, required := range []string{"--cpus 2", "--memory 6g", "--memory-swap 6g", "GOMAXPROCS=2", "GOMEMLIMIT=4GiB", "GOGC=25"} {
		if !strings.Contains(joined, required) {
			t.Errorf("runtime arguments missing %q: %s", required, joined)
		}
	}
}

func TestDockerRuntimeCapacityFailsBeforeProofWork(t *testing.T) {
	limits := dockerRuntimeLimits{CPUs: 2, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	ready := dockerDaemonFacts{MemoryLimit: true, SwapLimit: true, CPUQuota: true, MemoryBytes: int64(8) << 30, CPUs: 4}
	if err := validateDockerRuntimeCapacity(ready, limits); err != nil {
		t.Fatalf("capable daemon rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*dockerDaemonFacts)
	}{
		{"memory control", func(f *dockerDaemonFacts) { f.MemoryLimit = false }},
		{"swap control", func(f *dockerDaemonFacts) { f.SwapLimit = false }},
		{"cpu quota", func(f *dockerDaemonFacts) { f.CPUQuota = false }},
		{"daemon memory", func(f *dockerDaemonFacts) { f.MemoryBytes = int64(5) << 30 }},
		{"daemon cpus", func(f *dockerDaemonFacts) { f.CPUs = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := ready
			test.change(&facts)
			if err := validateDockerRuntimeCapacity(facts, limits); err == nil {
				t.Fatal("incapable Docker daemon accepted")
			}
		})
	}
}

func TestDockerRoleAndParticipantUseSameRuntimeLimits(t *testing.T) {
	roleArgs, err := dockerRoleArgs(roleTestOptions(t), []string{"relay", "help"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	driverArgs := (&dockerDriver{platform: "linux/amd64"}).securityArgs(nil)
	want := strings.Join(dockerRuntimeArgs(), " ")
	if !strings.Contains(strings.Join(roleArgs, " "), want) {
		t.Fatalf("role launcher lost runtime limits: %v", roleArgs)
	}
	if !strings.Contains(strings.Join(driverArgs, " "), want) {
		t.Fatalf("participant driver lost runtime limits: %v", driverArgs)
	}
}

func TestDirectProofInspectionUsesRuntimeLimitsExactlyOnce(t *testing.T) {
	args := dockerProofInspectionArgs("/private/input", "image@sha256:digest", "linux/arm64", []string{"definition", "--ceremony", "/input/ceremony.json"})
	for _, value := range []string{"--cpus", "--memory", "--memory-swap", "GOMAXPROCS=2", "GOMEMLIMIT=4GiB", "GOGC=25"} {
		count := 0
		for _, arg := range args {
			if arg == value {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%q occurs %d times in direct proof invocation: %v", value, count, args)
		}
	}
	image := -1
	for index, value := range args {
		if value == "image@sha256:digest" {
			image = index
		}
	}
	if image < 0 || image+1 >= len(args) || args[image+1] != "definition" {
		t.Fatalf("image/command boundary changed: %v", args)
	}
}
