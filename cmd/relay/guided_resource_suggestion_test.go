package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestGuidedSuggestionHonorsValidatedDefaultsCapsAndClaims(t *testing.T) {
	facts := dockerDaemonFacts{ID: "daemon", CPUs: 10, MemoryBytes: 8 << 30, CPUQuota: true, MemoryLimit: true, SwapLimit: true}
	caps := dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	got, err := suggestedGuidedResources(&caps, facts, nil, nil)
	if err != nil || got == nil || got.CPUs != 2 || got.MemoryGiB != 6 {
		t.Fatal("unvalidated higher allocation suggested", got, err)
	}
	lowCPU := caps
	lowCPU.CPUs = 1
	lowMemory := caps
	lowMemory.MemoryGiB = 5
	lowMemory.GoMemoryGiB = 3
	claim := dockerCapacityContainer{ID: strings.Repeat("a", 64)}
	claim.State.Status = "created"
	claim.HostConfig.NanoCPUs = 2_000_000_000
	claim.HostConfig.Memory = 6 << 30
	unknown := claim
	unknown.HostConfig.Memory = 0
	for _, tc := range []struct {
		name   string
		caps   dockerRuntimeLimits
		claims []dockerCapacityContainer
		policy *dockerResourcePolicy
	}{
		{name: "CPU cap", caps: lowCPU},
		{name: "memory cap", caps: lowMemory},
		{name: "outstanding claim", caps: caps, claims: []dockerCapacityContainer{claim}},
		{name: "unknown workload", caps: caps, claims: []dockerCapacityContainer{unknown}},
		{name: "explicit operator budget", caps: caps, policy: &dockerResourcePolicy{Mode: "operator-budget"}},
		{name: "invalid policy", caps: caps, policy: &dockerResourcePolicy{Mode: "strict"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := suggestedGuidedResources(&tc.caps, facts, tc.claims, tc.policy); err == nil || got != nil {
				t.Fatal("unsafe suggestion offered", got, err)
			}
		})
	}
}

func TestGuidedSuggestionRequiresExplicitSelection(t *testing.T) {
	facts := dockerDaemonFacts{CPUs: 10, MemoryBytes: 8 << 30, CPUQuota: true, MemoryLimit: true, SwapLimit: true}
	caps := dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	suggestion, err := suggestedGuidedResources(&caps, facts, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input string
		cpus  int
	}{{"1\n", 6}, {"s\n", 2}} {
		var out bytes.Buffer
		ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader(tc.input)), output: &out}
		selected, err := chooseGuidedResources(&ui, &caps, facts, suggestion)
		if err != nil || selected.CPUs != tc.cpus {
			t.Fatal("suggestion changed explicit choice", err)
		}
		if caps.CPUs != 6 {
			t.Fatal("suggestion mutated saved preferences")
		}
		if !strings.Contains(out.String(), "not a reservation") {
			t.Fatal("capacity snapshot presented as reserved")
		}
	}
	ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("S\n")), output: new(bytes.Buffer)}
	if _, err := chooseGuidedResources(&ui, &caps, facts, nil); err == nil {
		t.Fatal("unavailable suggestion accepted")
	}
}
