package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A single daemon uses one local lock path even when reached through different
// Unix socket aliases. The private directory deliberately refuses cooperation
// across OS users; silently using per-user locks would permit double admission.
// Remote/multi-host admission is not supported by this local protocol.
func acquireDockerAdmission(facts dockerDaemonFacts) (*participantRunLock, error) {
	if facts.ID == "" {
		return nil, errors.New("Docker admission requires authenticated daemon identity")
	}
	if err := validateLocalDockerEndpoint(facts.Endpoint); err != nil {
		return nil, err
	}
	return acquireDockerAdmissionAt("/tmp", facts.ID)
}

func acquireDockerAdmissionAt(root, daemonID string) (*participantRunLock, error) {
	if !filepath.IsAbs(root) || daemonID == "" {
		return nil, errors.New("invalid Docker admission lock identity")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(daemonID)))
	lock, err := acquireParticipantRunLock("", filepath.Join(root, "relay-docker-admission-"+digest))
	if err != nil {
		return nil, fmt.Errorf("Docker admission is unavailable; another local admission may be active or the shared lock directory may belong to another OS user: %w", err)
	}
	return lock, nil
}

// Caller holds this lock through workload creation and ID persistence. The
// actual created container then carries the reservation after releasing it.
func acquireDockerCapacity(client dockerCommandClient, facts dockerDaemonFacts, limits dockerRuntimeLimits) (*participantRunLock, error) {
	if err := validateDockerRuntimeCapacity(facts, limits); err != nil {
		return nil, err
	}
	lock, err := acquireDockerAdmission(facts)
	if err != nil {
		return nil, err
	}
	// Keep one CPU and one GiB outside ceremony allocations. These are safety
	// reserves, not a claim that arbitrary host workloads fit within them.
	containers, err := inspectDockerCapacityContainers(client)
	var remaining dockerRemainingCapacity
	if err == nil {
		policy, policyErr := readDockerResourcePolicy(facts.ID)
		if policyErr != nil {
			err = policyErr
		} else {
			remaining, err = remainingDockerPolicyCapacity(facts, containers, dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}, policy)
		}
	}
	if err == nil && (int64(limits.CPUs)*1_000_000_000 > remaining.CPUNano || int64(limits.MemoryGiB)<<30 > remaining.MemoryBytes) {
		err = fmt.Errorf("insufficient unclaimed Docker capacity for %d CPUs and %d GiB; wait for other workloads or lower limits", limits.CPUs, limits.MemoryGiB)
	}
	if err != nil {
		_ = lock.release()
		return nil, fmt.Errorf("Docker resource admission: %w (review with relay resources)", err)
	}
	return lock, nil
}

func dockerResourcePolicyPath(daemonID string) string {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(daemonID)))
	return filepath.Join("/tmp", "relay-docker-admission-"+digest, "resource-policy.json")
}

// Caller holds daemon admission. Absence preserves strict behavior; malformed
// policy is never treated as permission to ignore external workloads.
func readDockerResourcePolicy(daemonID string) (*dockerResourcePolicy, error) {
	if daemonID == "" {
		return nil, errors.New("resource policy requires daemon identity")
	}
	var policy dockerResourcePolicy
	err := readWorkflowV4JSON(dockerResourcePolicyPath(daemonID), &policy)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &policy, nil
}
