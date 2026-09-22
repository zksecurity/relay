package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func configureGuidedResourcePolicy(ui *coordinatorWizard, client dockerCommandClient, facts dockerDaemonFacts) error {
	containers, err := inspectDockerCapacityContainers(client)
	if err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "1) Strict capacity accounting\n2) Assign an explicit aggregate Relay budget")
	answer, err := ui.ask("Daemon resource policy", "1")
	if err != nil {
		return err
	}
	policy := dockerResourcePolicy{Schema: dockerResourcePolicySchema, Mode: "strict", DaemonID: facts.ID, CPUs: facts.CPUs, MemoryBytes: facts.MemoryBytes}
	switch strings.TrimSpace(answer) {
	case "1":
	case "2":
		fmt.Fprintln(ui.output, "Other containers may have no resource limits. Relay cannot determine safe spare capacity. An explicit budget limits all Relay jobs together; other services may still compete for memory. Automatic recommendations are disabled in this mode.")
		cpu, err := ui.ask("Aggregate Relay CPU budget", "2")
		if err != nil {
			return err
		}
		memory, err := ui.ask("Aggregate Relay memory budget (GiB)", "6")
		if err != nil {
			return err
		}
		cpus, err := strconv.Atoi(cpu)
		if err != nil || cpus < 1 || cpus > 1024 {
			return errors.New("invalid Relay CPU budget")
		}
		gib, err := strconv.Atoi(memory)
		if err != nil || gib < 1 || gib > 65536 {
			return errors.New("invalid Relay memory budget")
		}
		policy.Mode = "operator-budget"
		policy.Budget = dockerRemainingCapacity{CPUNano: int64(cpus) * 1_000_000_000, MemoryBytes: int64(gib) << 30}
		policy.Unknown = map[string]string{}
		for _, c := range containers {
			if c.State.Status == "exited" || c.State.Status == "dead" {
				continue
			}
			if c.HostConfig.NanoCPUs == 0 || c.HostConfig.Memory == 0 {
				if c.Config.Labels["org.zksecurity.relay.role"] != "" {
					return errors.New("unbounded Relay workload must be resolved before assigning a budget")
				}
				policy.Unknown[c.ID] = dockerUnknownWorkloadDigest(c)
				fmt.Fprintf(ui.output, "Unbounded external workload: %s (%s)\n", shortContainerID(c.ID), c.State.Status)
			}
		}
		if err := ui.confirm("Assign this aggregate budget despite competition from the listed external workloads", "ASSIGN RELAY BUDGET"); err != nil {
			return err
		}
		policy.AcknowledgedAt = time.Now().UTC().Format(time.RFC3339)
	default:
		return errors.New("choose resource policy 1 or 2")
	}
	lock, err := acquireDockerAdmission(facts)
	if err != nil {
		return err
	}
	defer lock.release()
	// Reinspect after the prompt. New/changed unknown workloads invalidate the
	// acknowledgment instead of inheriting consent from the earlier snapshot.
	current, err := inspectDockerDaemon(client, facts.Context, facts.Endpoint)
	if err != nil {
		return err
	}
	if current.ID != facts.ID || current.CPUs != facts.CPUs || current.MemoryBytes != facts.MemoryBytes {
		return errors.New("Docker capacity changed while selecting policy; review again")
	}
	fresh, err := inspectDockerCapacityContainers(client)
	if err != nil {
		return err
	}
	if policy.Mode == "operator-budget" {
		if _, err := remainingDockerPolicyCapacity(current, fresh, dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}, &policy); err != nil {
			return err
		}
	}
	if err := writeJSONAtomic(dockerResourcePolicyPath(facts.ID), policy, 0600); err != nil {
		return err
	}
	fmt.Fprintln(ui.output, "Saved daemon resource policy for new admissions. Existing containers are unchanged.")
	return nil
}

// Check policy before the first proof-backed storage/definition inspection so
// a host with unknown external workloads can reach the policy choice at all.
func ensureGuidedResourcePolicy(ui *coordinatorWizard, client dockerCommandClient, facts dockerDaemonFacts) error {
	lock, err := acquireDockerAdmission(facts)
	if err != nil {
		return err
	}
	containers, checkErr := inspectDockerCapacityContainers(client)
	var policy *dockerResourcePolicy
	if checkErr == nil {
		policy, checkErr = readDockerResourcePolicy(facts.ID)
	}
	if checkErr == nil {
		_, checkErr = remainingDockerPolicyCapacity(facts, containers, dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}, policy)
	}
	releaseErr := lock.release()
	if releaseErr != nil {
		return releaseErr
	}
	if checkErr == nil {
		return nil
	}
	fmt.Fprintf(ui.output, "Resource policy requires review before launching proof work: %v\n", checkErr)
	return configureGuidedResourcePolicy(ui, client, facts)
}
