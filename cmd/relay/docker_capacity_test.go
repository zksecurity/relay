package main

import (
	"strings"
	"testing"
)

func TestDockerCapacityCountsOutstandingWorkloads(t *testing.T) {
	facts := dockerDaemonFacts{CPUs: 10, MemoryBytes: 8 << 30}
	reserve := dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}
	for _, state := range []string{"created", "running", "paused", "restarting", "removing", "exited", "dead"} {
		t.Run(state, func(t *testing.T) {
			c := dockerCapacityContainer{ID: strings.Repeat("a", 64)}
			c.State.Status = state
			c.HostConfig.NanoCPUs = 2_000_000_000
			c.HostConfig.Memory = 6 << 30
			remaining, err := remainingDockerCapacity(facts, []dockerCapacityContainer{c}, reserve)
			if err != nil {
				t.Fatal(err)
			}
			wantMemory := int64(1 << 30)
			wantCPU := int64(7_000_000_000)
			if state == "exited" || state == "dead" {
				wantMemory = 7 << 30
				wantCPU = 9_000_000_000
			}
			if remaining.MemoryBytes != wantMemory || remaining.CPUNano != wantCPU {
				t.Fatalf("wrong accounting: %+v", remaining)
			}
		})
	}
}

func TestDockerCapacityRejectsUncertainOrOvercommittedInventory(t *testing.T) {
	facts := dockerDaemonFacts{CPUs: 10, MemoryBytes: 8 << 30}
	c := dockerCapacityContainer{ID: strings.Repeat("a", 64)}
	c.State.Status = "running"
	c.HostConfig.NanoCPUs = 6_000_000_000
	c.HostConfig.Memory = 6 << 30
	for _, alter := range []func(*dockerCapacityContainer){
		func(c *dockerCapacityContainer) { c.HostConfig.NanoCPUs = 0 },
		func(c *dockerCapacityContainer) { c.HostConfig.Memory = 0 },
		func(c *dockerCapacityContainer) { c.State.Status = "unknown" },
		func(c *dockerCapacityContainer) { c.HostConfig.Memory = 1 << 62 },
		func(c *dockerCapacityContainer) { c.ID = "short" },
	} {
		bad := c
		alter(&bad)
		if _, err := remainingDockerCapacity(facts, []dockerCapacityContainer{bad}, dockerRemainingCapacity{}); err == nil {
			t.Fatal("uncertain inventory accepted", bad)
		}
	}
	second := c
	second.ID = strings.Repeat("b", 64)
	if _, err := remainingDockerCapacity(facts, []dockerCapacityContainer{c, second}, dockerRemainingCapacity{}); err == nil {
		t.Fatal("combined oversubscription accepted")
	}
	if _, err := remainingDockerCapacity(facts, []dockerCapacityContainer{c, c}, dockerRemainingCapacity{}); err == nil {
		t.Fatal("duplicate inventory accepted")
	}
}
