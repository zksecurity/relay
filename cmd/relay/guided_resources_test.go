package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuidedResourcesCapacityAndSavedCaps(t *testing.T) {
	facts := dockerDaemonFacts{CPUs: 10, MemoryBytes: 8 << 30, MemoryLimit: true, SwapLimit: true, CPUQuota: true}
	for _, tc := range []struct {
		name, input  string
		cpus, memory int
		reject       bool
	}{
		{"keep", "1\n", 4, 6, false},
		{"adjust", "2\n6\n6\n", 6, 6, false},
		{"conservative", "3\n", 2, 6, false},
		{"too many CPUs", "2\n11\n6\n", 0, 0, true},
		{"too much memory", "2\n6\n9\n", 0, 0, true},
		{"invalid CPU", "2\n0\n6\n", 0, 0, true},
		{"invalid input", "2\nauto\n6\n", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := dockerRuntimeLimits{CPUs: 4, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
			var output bytes.Buffer
			ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader(tc.input)), output: &output}
			got, err := chooseGuidedResources(&ui, &saved, facts)
			if tc.reject {
				if err == nil {
					t.Fatal("invalid allocation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.CPUs != tc.cpus || got.MemoryGiB != tc.memory {
				t.Fatalf("wrong limits: %+v", got)
			}
			if saved.CPUs != 4 {
				t.Fatal("selection mutated saved profile before persistence")
			}
			if !strings.Contains(output.String(), "total memory") {
				t.Fatal("capacity presented as available memory")
			}
		})
	}
	facts.MemoryBytes = 4 << 30
	ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("3\n")), output: new(bytes.Buffer)}
	if _, err := chooseGuidedResources(&ui, nil, facts); err == nil {
		t.Fatal("conservative allocation accepted on insufficient host")
	}
}

func TestGuidedActionRetainsResourcesAcrossPreferenceChanges(t *testing.T) {
	dir := t.TempDir()
	command := []string{"mpc-ceremony", "help"}
	selected := dockerRuntimeLimits{CPUs: 6, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	profile := guidedProfile{Resources: &selected}
	if _, _, err := prepareGuidedAction(dir, "derive", command, profile); err != nil {
		t.Fatal(err)
	}
	selected.CPUs = 4
	if _, _, err := prepareGuidedAction(dir, "derive", nil, profile); err != nil {
		t.Fatal(err)
	}
	saved, err := readGuidedProfile(filepath.Join(dir, "actions", "derive", "profile.json"), "derive", "action")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Resources == nil || saved.Resources.CPUs != 6 {
		t.Fatal("changed original action allocation")
	}
	if _, _, err := prepareGuidedAction(dir, "next", command, profile); err != nil {
		t.Fatal(err)
	}
	next, err := readGuidedProfile(filepath.Join(dir, "actions", "next", "profile.json"), "next", "action")
	if err != nil {
		t.Fatal(err)
	}
	if next.Resources == nil || next.Resources.CPUs != 4 {
		t.Fatal("new action ignored selected allocation")
	}
	if _, _, err := prepareGuidedAction(dir, "legacy", command); err != nil {
		t.Fatal(err)
	}
	legacy, err := readGuidedProfile(filepath.Join(dir, "actions", "legacy", "profile.json"), "legacy", "action")
	if err != nil {
		t.Fatal(err)
	}
	limits, err := resolvedDockerRuntimeLimits(legacy.Resources)
	if err != nil || limits.CPUs != 2 {
		t.Fatal("legacy action allocation changed")
	}
}
