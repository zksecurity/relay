package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const dockerResourcePolicySchema = "relay-docker-resource-policy-v1"

type dockerResourcePolicy struct {
	Schema         string                  `json:"schema"`
	Mode           string                  `json:"mode"`
	DaemonID       string                  `json:"daemon_id"`
	CPUs           int                     `json:"daemon_cpus"`
	MemoryBytes    int64                   `json:"daemon_memory_bytes"`
	Budget         dockerRemainingCapacity `json:"relay_budget"`
	Unknown        map[string]string       `json:"acknowledged_unknown_workloads"`
	AcknowledgedAt string                  `json:"acknowledged_at"`
}

func dockerUnknownWorkloadDigest(c dockerCapacityContainer) string {
	raw, _ := json.Marshal(struct {
		ID, Status, Role string
		CPU, Memory      int64
	}{
		c.ID, c.State.Status, c.Config.Labels["org.zksecurity.relay.role"], c.HostConfig.NanoCPUs, c.HostConfig.Memory})
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}

// Operator budget explicitly accepts competition from the acknowledged external
// workloads. It cannot authorize unbounded Relay jobs or excess aggregate claims.
func remainingDockerPolicyCapacity(facts dockerDaemonFacts, containers []dockerCapacityContainer, reserve dockerRemainingCapacity, policy *dockerResourcePolicy) (dockerRemainingCapacity, error) {
	if _, err := remainingDockerCapacity(facts, nil, reserve); err != nil {
		return dockerRemainingCapacity{}, err
	}
	if policy == nil {
		return remainingDockerCapacity(facts, containers, reserve)
	}
	if policy.Schema != dockerResourcePolicySchema || policy.DaemonID != facts.ID || policy.CPUs != facts.CPUs || policy.MemoryBytes != facts.MemoryBytes {
		return dockerRemainingCapacity{}, errors.New("Docker resource policy does not match this daemon and capacity; review resource policy")
	}
	if policy.Mode == "strict" {
		return remainingDockerCapacity(facts, containers, reserve)
	}
	if policy.Mode != "operator-budget" {
		return dockerRemainingCapacity{}, errors.New("unknown Docker resource policy mode")
	}
	if _, err := time.Parse(time.RFC3339, policy.AcknowledgedAt); err != nil {
		return dockerRemainingCapacity{}, errors.New("operator budget requires recorded acknowledgment")
	}
	if policy.Budget.CPUNano <= 0 || policy.Budget.MemoryBytes <= 0 || policy.Budget.CPUNano > int64(facts.CPUs)*1_000_000_000 || policy.Budget.MemoryBytes > facts.MemoryBytes {
		return dockerRemainingCapacity{}, errors.New("invalid aggregate Relay resource budget")
	}
	budget := policy.Budget
	bounded := make([]dockerCapacityContainer, 0, len(containers))
	seen := map[string]bool{}
	for _, c := range containers {
		if !validContainerID(c.ID) || seen[c.ID] {
			return dockerRemainingCapacity{}, errors.New("invalid or repeated container in policy inventory")
		}
		seen[c.ID] = true
		switch c.State.Status {
		case "exited", "dead":
			continue
		case "created", "running", "paused", "restarting", "removing":
		default:
			return dockerRemainingCapacity{}, errors.New("unknown workload status in policy inventory")
		}
		if acknowledged, ok := policy.Unknown[c.ID]; ok && acknowledged != dockerUnknownWorkloadDigest(c) {
			return dockerRemainingCapacity{}, errors.New("acknowledged workload changed; review operator budget acknowledgment")
		}
		relay := c.Config.Labels["org.zksecurity.relay.role"] != ""
		if c.HostConfig.NanoCPUs < 0 || c.HostConfig.Memory < 0 {
			return dockerRemainingCapacity{}, errors.New("invalid workload resource limits")
		}
		if c.HostConfig.NanoCPUs == 0 || c.HostConfig.Memory == 0 {
			if relay {
				return dockerRemainingCapacity{}, errors.New("Relay workload has unbounded resources")
			}
			if policy.Unknown[c.ID] != dockerUnknownWorkloadDigest(c) {
				return dockerRemainingCapacity{}, errors.New("unbounded workload is new or changed; review operator budget acknowledgment")
			}
			// Even a partly unbounded workload can have one known limit; account for it.
			if c.HostConfig.NanoCPUs > int64(facts.CPUs)*1_000_000_000-reserve.CPUNano || c.HostConfig.Memory > facts.MemoryBytes-reserve.MemoryBytes {
				return dockerRemainingCapacity{}, errors.New("external workload consumes remaining capacity")
			}
			reserve.CPUNano += c.HostConfig.NanoCPUs
			reserve.MemoryBytes += c.HostConfig.Memory
			continue
		}
		bounded = append(bounded, c)
		if relay {
			// A reduced budget can be saved while older jobs still run. They
			// remain untouched, but leave no capacity for another admission.
			budget.CPUNano = max(int64(0), budget.CPUNano-c.HostConfig.NanoCPUs)
			budget.MemoryBytes = max(int64(0), budget.MemoryBytes-c.HostConfig.Memory)
		}
	}
	remaining, err := remainingDockerCapacity(facts, bounded, reserve)
	if err != nil {
		return dockerRemainingCapacity{}, err
	}
	if budget.CPUNano < remaining.CPUNano {
		remaining.CPUNano = budget.CPUNano
	}
	if budget.MemoryBytes < remaining.MemoryBytes {
		remaining.MemoryBytes = budget.MemoryBytes
	}
	return remaining, nil
}
