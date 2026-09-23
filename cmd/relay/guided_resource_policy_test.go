package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuidedOperatorBudgetPersistsAndEnablesAdmission(t *testing.T) {
	daemon := "policy-test-" + t.TempDir()
	fake := &dockerClientFake{daemonID: daemon}
	external := dockerCapacityContainer{ID: strings.Repeat("a", 64)}
	external.State.Status = "running"
	fake.capacityContainers = []dockerCapacityContainer{external}
	facts, err := inspectDockerDaemon(fake, "test-local", "unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(dockerResourcePolicyPath(daemon))) })
	var out bytes.Buffer
	ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("2\n4\n6\nASSIGN RELAY BUDGET\n")), output: &out}
	if err := ensureGuidedResourcePolicy(&ui, fake, facts); err != nil {
		t.Fatal(err)
	}
	saved, err := readDockerResourcePolicy(daemon)
	if err != nil || saved == nil || saved.Mode != "operator-budget" || len(saved.Unknown) != 1 {
		t.Fatal("policy missing", err)
	}
	limits := dockerRuntimeLimits{CPUs: 2, MemoryGiB: 6, GoMemoryGiB: 4, GoGCPercent: 25}
	lock, err := acquireDockerCapacity(fake, facts, limits)
	if err != nil {
		t.Fatal("acknowledged external workload still blocked", err)
	}
	lock.release()
	noInput := coordinatorWizard{input: bufio.NewReader(strings.NewReader("")), output: &out}
	if err := ensureGuidedResourcePolicy(&noInput, fake, facts); err != nil {
		t.Fatal("unchanged policy prompted again", err)
	}

	fake.capacityContainers[0].ID = strings.Repeat("b", 64)
	if lock, err := acquireDockerCapacity(fake, facts, limits); err == nil {
		lock.release()
		t.Fatal("replacement workload inherited acknowledgment")
	}
	// Refusing confirmation must neither replace nor discard the saved policy.
	ui = coordinatorWizard{input: bufio.NewReader(strings.NewReader("2\n4\n6\nNO\n")), output: &out}
	if err := configureGuidedResourcePolicy(&ui, fake, facts); err == nil {
		t.Fatal("budget saved without confirmation")
	}
	retained, err := readDockerResourcePolicy(daemon)
	if err != nil || retained.Unknown[external.ID] != saved.Unknown[external.ID] {
		t.Fatal("rejected confirmation altered saved policy", err)
	}
	if !strings.Contains(out.String(), "Automatic recommendations are disabled") {
		t.Fatal("operator budget uncertainty omitted")
	}
}
