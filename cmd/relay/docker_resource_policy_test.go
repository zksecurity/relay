package main

import (
	"strings"
	"testing"
)

func TestDockerOperatorBudgetRequiresExactAcknowledgment(t *testing.T) {
	facts := dockerDaemonFacts{ID: "daemon", CPUs: 10, MemoryBytes: 8 << 30}
	external := dockerCapacityContainer{ID: strings.Repeat("a", 64)}
	external.State.Status = "running"
	policy := dockerResourcePolicy{Schema: dockerResourcePolicySchema, Mode: "operator-budget", DaemonID: facts.ID, CPUs: facts.CPUs, MemoryBytes: facts.MemoryBytes, Budget: dockerRemainingCapacity{CPUNano: 6_000_000_000, MemoryBytes: 6 << 30}, Unknown: map[string]string{external.ID: dockerUnknownWorkloadDigest(external)}, AcknowledgedAt: "2026-09-23T00:00:00Z"}
	reserve := dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}
	if _, err := remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external}, reserve, nil); err == nil {
		t.Fatal("strict policy accepted unknown workload")
	}
	remaining, err := remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external}, reserve, &policy)
	if err != nil || remaining != policy.Budget {
		t.Fatalf("acknowledged budget rejected: %+v %v", remaining, err)
	}
	for _, change := range []func(*dockerCapacityContainer){
		func(c *dockerCapacityContainer) { c.ID = strings.Repeat("b", 64) },
		func(c *dockerCapacityContainer) { c.State.Status = "paused" },
		func(c *dockerCapacityContainer) { c.HostConfig.Memory = 1 << 30 },
		func(c *dockerCapacityContainer) { c.HostConfig.Memory = 1 << 30; c.HostConfig.NanoCPUs = 1_000_000_000 },
		func(c *dockerCapacityContainer) {
			c.Config.Labels = map[string]string{"org.zksecurity.relay.role": "participant-contributor"}
		},
	} {
		changed := external
		change(&changed)
		if _, err := remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{changed}, reserve, &policy); err == nil {
			t.Fatal("changed unknown workload accepted")
		}
	}
	if _, err := remainingDockerPolicyCapacity(facts, nil, reserve, &policy); err != nil {
		t.Fatal("removed unknown workload forced acknowledgment", err)
	}
	for _, change := range []func(*dockerResourcePolicy){
		func(p *dockerResourcePolicy) { p.DaemonID = "replacement" },
		func(p *dockerResourcePolicy) { p.MemoryBytes-- },
		func(p *dockerResourcePolicy) { p.Schema = "future" },
		func(p *dockerResourcePolicy) { p.Mode = "auto-bypass" },
		func(p *dockerResourcePolicy) { p.AcknowledgedAt = "" },
		func(p *dockerResourcePolicy) { p.Budget.MemoryBytes = 0 },
	} {
		changed := policy
		change(&changed)
		if _, err := remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external}, reserve, &changed); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	relay := dockerCapacityContainer{ID: strings.Repeat("c", 64)}
	relay.State.Status = "created"
	relay.Config.Labels = map[string]string{"org.zksecurity.relay.role": "participant-contributor"}
	relay.HostConfig.NanoCPUs = 2_000_000_000
	relay.HostConfig.Memory = 4 << 30
	remaining, err = remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external, relay}, reserve, &policy)
	if err != nil || remaining.MemoryBytes != 2<<30 || remaining.CPUNano != 4_000_000_000 {
		t.Fatalf("aggregate claims not subtracted: %+v %v", remaining, err)
	}
	other := relay
	other.ID = strings.Repeat("d", 64)
	// Two claims exceed both this host's remaining memory and the budget.
	if _, err := remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external, relay, other}, reserve, &policy); err == nil {
		t.Fatal("host capacity exceeded")
	}
	reduced := policy
	reduced.Budget.MemoryBytes = 2 << 30
	remaining, err = remainingDockerPolicyCapacity(facts, []dockerCapacityContainer{external, relay}, reserve, &reduced)
	if err != nil || remaining.MemoryBytes != 0 {
		t.Fatalf("reduced budget should block new work without invalidating existing jobs: %+v %v", remaining, err)
	}
}
