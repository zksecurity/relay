package main

import "errors"

// Recommendations are deliberately limited to the released allocation. Larger
// CPU counts require measurements before joining the validated candidate set.
func suggestedGuidedResources(current *dockerRuntimeLimits, facts dockerDaemonFacts, containers []dockerCapacityContainer, policy *dockerResourcePolicy) (*dockerRuntimeLimits, error) {
	caps, err := resolvedDockerRuntimeLimits(current)
	if err != nil {
		return nil, err
	}
	if policy != nil && policy.Mode == "operator-budget" {
		return nil, errors.New("automatic suggestions are disabled for an operator-assigned budget")
	}
	remaining, err := remainingDockerPolicyCapacity(facts, containers, dockerRemainingCapacity{CPUNano: 1_000_000_000, MemoryBytes: 1 << 30}, policy)
	if err != nil {
		return nil, err
	}
	candidate, err := resolvedDockerRuntimeLimits(nil)
	if err != nil {
		return nil, err
	}
	if candidate.CPUs > caps.CPUs || candidate.MemoryGiB > caps.MemoryGiB {
		return nil, errors.New("no validated allocation fits the saved limits; adjust explicitly or retain them")
	}
	if err := validateDockerRuntimeCapacity(facts, candidate); err != nil {
		return nil, err
	}
	if int64(candidate.CPUs)*1_000_000_000 > remaining.CPUNano || int64(candidate.MemoryGiB)<<30 > remaining.MemoryBytes {
		return nil, errors.New("no validated allocation fits the currently unclaimed capacity; wait or adjust explicitly")
	}
	return &candidate, nil
}

func inspectGuidedResourceSuggestion(current *dockerRuntimeLimits, client dockerCommandClient, facts dockerDaemonFacts) (*dockerRuntimeLimits, error) {
	lock, err := acquireDockerAdmission(facts)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	containers, err := inspectDockerCapacityContainers(client)
	if err != nil {
		return nil, err
	}
	policy, err := readDockerResourcePolicy(facts.ID)
	if err != nil {
		return nil, err
	}
	return suggestedGuidedResources(current, facts, containers, policy)
}
