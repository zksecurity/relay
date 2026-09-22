package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Explicit limits are persisted as preferences; the operation journal freezes
// the allocation actually used. Capacity here is total daemon capacity, not a
// claim that memory has been reserved or that a faster allocation is qualified.
func chooseGuidedResources(ui *coordinatorWizard, current *dockerRuntimeLimits, facts dockerDaemonFacts) (*dockerRuntimeLimits, error) {
	limits, err := resolvedDockerRuntimeLimits(current)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(ui.output, "Docker provides %d CPUs and %.2f GiB total memory.\nCurrent limits: %d CPUs, %d GiB memory.\n", facts.CPUs, float64(facts.MemoryBytes)/(1<<30), limits.CPUs, limits.MemoryGiB)
	fmt.Fprintln(ui.output, "1) Keep current limits\n2) Adjust resource limits\n3) Use conservative limits: 2 CPUs, 6 GiB\nTotal memory is not currently available memory. Leave capacity for other work.")
	answer, err := ui.ask("Resource choice", "1")
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(answer) {
	case "1":
	case "2":
		cpu, err := ui.ask("Maximum CPUs", strconv.Itoa(limits.CPUs))
		if err != nil {
			return nil, err
		}
		memory, err := ui.ask("Maximum container memory (GiB)", strconv.Itoa(limits.MemoryGiB))
		if err != nil {
			return nil, err
		}
		limits.CPUs, err = strconv.Atoi(cpu)
		if err != nil {
			return nil, errors.New("CPU limit must be a whole number")
		}
		limits.MemoryGiB, err = strconv.Atoi(memory)
		if err != nil {
			return nil, errors.New("memory limit must be a whole number of GiB")
		}
		limits.GoMemoryGiB = limits.MemoryGiB - 2
	case "3":
		limits, err = resolvedDockerRuntimeLimits(nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("choose resource option 1, 2, or 3")
	}
	if err := validateDockerRuntimeCapacity(facts, limits); err != nil {
		return nil, err
	}
	return &limits, nil
}
