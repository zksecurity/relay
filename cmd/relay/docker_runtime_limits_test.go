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

func TestSavedDockerRuntimeLimitsFailClosed(t *testing.T) {
	legacy, err := resolvedDockerRuntimeLimits(nil)
	if err != nil || legacy != proofDockerRuntimeLimits {
		t.Fatalf("legacy allocation: %v %v", legacy, err)
	}
	selected := dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	got, err := resolvedDockerRuntimeLimits(&selected)
	if err != nil || got != selected {
		t.Fatalf("saved allocation: %v %v", got, err)
	}
	for _, change := range []func(*dockerRuntimeLimits){
		func(l *dockerRuntimeLimits) { l.CPUs = 0 },
		func(l *dockerRuntimeLimits) { l.CPUs = 1025 },
		func(l *dockerRuntimeLimits) { l.MemoryGiB = 2 },
		func(l *dockerRuntimeLimits) { l.MemoryGiB = 65537 },
		func(l *dockerRuntimeLimits) { l.GoMemoryGiB = 5 },
		func(l *dockerRuntimeLimits) { l.GoGCPercent = 0 },
	} {
		bad := selected
		change(&bad)
		if _, err := resolvedDockerRuntimeLimits(&bad); err == nil {
			t.Fatalf("invalid saved allocation accepted: %+v", bad)
		}
	}
}

func TestDockerRoleUsesSelectedAllocation(t *testing.T) {
	o := roleTestOptions(t)
	o.runtimeLimits = &dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	args, err := dockerRoleArgs(o, []string{"relay", "help"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--cpus 6") || !strings.Contains(joined, "GOMAXPROCS=6") || strings.Contains(joined, "GOMAXPROCS=2") {
		t.Fatalf("wrong selected allocation: %s", joined)
	}
	o.runtimeLimits.GoMemoryGiB = 6
	if _, err := dockerRoleArgs(o, []string{"relay", "help"}, 501, 20); err == nil {
		t.Fatal("accepted memory target without headroom")
	}
}

func TestDockerRuntimeReceiptMatchesSavedAllocation(t *testing.T) {
	limits := dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	facts := dockerSecurityFacts{RuntimeLimitsVerified: true, CPULimitNano: 6_000_000_000,
		MemoryLimitBytes: 6 << 30, MemorySwapLimitBytes: 6 << 30, GoMaxProcs: "6", GoMemoryLimit: "4GiB", GoGCPercent: "25"}
	if !limits.matchesSecurityFacts(facts) {
		t.Fatal("saved allocation rejected")
	}
	for _, change := range []func(*dockerSecurityFacts){
		func(f *dockerSecurityFacts) { f.RuntimeLimitsVerified = false },
		func(f *dockerSecurityFacts) { f.CPULimitNano = 2_000_000_000 },
		func(f *dockerSecurityFacts) { f.MemoryLimitBytes = 8 << 30 },
		func(f *dockerSecurityFacts) { f.MemorySwapLimitBytes = 8 << 30 },
		func(f *dockerSecurityFacts) { f.GoMaxProcs = "2" },
		func(f *dockerSecurityFacts) { f.GoMemoryLimit = "5GiB" },
		func(f *dockerSecurityFacts) { f.GoGCPercent = "100" },
	} {
		altered := facts
		change(&altered)
		if limits.matchesSecurityFacts(altered) {
			t.Fatalf("changed resource evidence accepted: %+v", altered)
		}
	}
	later := limits
	later.CPUs = 4
	if later.matchesSecurityFacts(facts) {
		t.Fatal("later preferences accepted for earlier operation")
	}
}
