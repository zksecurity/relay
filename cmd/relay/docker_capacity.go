package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type dockerCapacityContainer struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
	HostConfig struct {
		NanoCPUs int64 `json:"NanoCpus"`
		Memory   int64 `json:"Memory"`
	} `json:"HostConfig"`
}

type dockerRemainingCapacity struct {
	CPUNano     int64 `json:"cpu_nano"`
	MemoryBytes int64 `json:"memory_bytes"`
}

// Accounting must run under the admission lock, immediately before create.
// Created containers are claims too: a crash before start must not free them.
// This does not prevent noncooperating clients from launching concurrently.
func remainingDockerCapacity(facts dockerDaemonFacts, containers []dockerCapacityContainer, reserve dockerRemainingCapacity) (dockerRemainingCapacity, error) {
	if facts.CPUs < 1 || facts.CPUs > 1024 || facts.MemoryBytes <= 0 || reserve.CPUNano < 0 || reserve.MemoryBytes < 0 {
		return dockerRemainingCapacity{}, errors.New("invalid Docker capacity or host reserve")
	}
	remaining := dockerRemainingCapacity{CPUNano: int64(facts.CPUs) * 1_000_000_000, MemoryBytes: facts.MemoryBytes}
	if reserve.CPUNano > remaining.CPUNano || reserve.MemoryBytes > remaining.MemoryBytes {
		return dockerRemainingCapacity{}, errors.New("Docker capacity is below the host reserve")
	}
	remaining.CPUNano -= reserve.CPUNano
	remaining.MemoryBytes -= reserve.MemoryBytes
	seen := make(map[string]bool)
	for _, c := range containers {
		if !validContainerID(c.ID) || seen[c.ID] {
			return dockerRemainingCapacity{}, errors.New("invalid or repeated container in capacity inspection")
		}
		seen[c.ID] = true
		switch c.State.Status {
		case "exited", "dead":
			continue
		case "created", "running", "paused", "restarting", "removing":
		default:
			return dockerRemainingCapacity{}, errors.New("unknown container state prevents capacity admission")
		}
		if c.HostConfig.NanoCPUs <= 0 || c.HostConfig.Memory <= 0 {
			return dockerRemainingCapacity{}, fmt.Errorf("container %s has unbounded resources; available capacity is unknown", shortContainerID(c.ID))
		}
		if c.HostConfig.NanoCPUs > remaining.CPUNano || c.HostConfig.Memory > remaining.MemoryBytes {
			return dockerRemainingCapacity{}, errors.New("existing container limits consume the available Docker capacity")
		}
		remaining.CPUNano -= c.HostConfig.NanoCPUs
		remaining.MemoryBytes -= c.HostConfig.Memory
	}
	return remaining, nil
}

func inspectDockerCapacityContainers(client dockerCommandClient) ([]dockerCapacityContainer, error) {
	raw, stderr, err := client.Output("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("list workloads for resource admission: %s", dockerDiagnostic(stderr, err))
	}
	ids := strings.Fields(string(raw))
	containers := make([]dockerCapacityContainer, 0, len(ids))
	// Inspect one ID at a time to avoid command-line size limits. A disappearing
	// container makes this snapshot uncertain; the next admission can retry.
	for _, id := range ids {
		if !validContainerID(id) {
			return nil, errors.New("invalid Docker capacity inventory")
		}
		raw, stderr, err := client.Output("inspect", id)
		if err != nil {
			return nil, fmt.Errorf("inspect workload capacity: %s", dockerDiagnostic(stderr, err))
		}
		var records []dockerCapacityContainer
		if err := json.Unmarshal(raw, &records); err != nil || len(records) != 1 || records[0].ID != id {
			return nil, errors.New("Docker capacity inspection identity mismatch")
		}
		containers = append(containers, records[0])
	}
	return containers, nil
}

func inspectDockerCapacity(client dockerCommandClient, facts dockerDaemonFacts, reserve dockerRemainingCapacity) (dockerRemainingCapacity, error) {
	containers, err := inspectDockerCapacityContainers(client)
	if err != nil {
		return dockerRemainingCapacity{}, err
	}
	return remainingDockerCapacity(facts, containers, reserve)
}
