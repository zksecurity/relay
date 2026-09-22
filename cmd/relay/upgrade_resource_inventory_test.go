package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpgradeInventoryPreservesResourceRecovery(t *testing.T) {
	s, d := testUpgradeV2(t, "participant")
	before, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	resource := workflowV4CommandResources{Schema: "relay-command-resources-v1", CommandDigest: digest, Limits: proofDockerRuntimeLimits}
	resourcePath := filepath.Join(s.Profile.Work, "workflow-v4", "resources", digest+".json")
	if err := writeJSONAtomic(resourcePath, resource, 0600); err != nil {
		t.Fatal(err)
	}
	role := dockerRoleLaunchRecord{Schema: "relay-role-launch-v1", DaemonID: "daemon", Name: "relay-role-" + digest[:32], ContainerID: testContainerID, ArgsDigest: "sha256:" + strings.Repeat("b", 64)}
	rolePath := filepath.Join(s.Profile.Work, "workflow-v4", "role-launches", digest+".json")
	if err := writeJSONAtomic(rolePath, role, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	if after.digest() == before.digest() {
		t.Fatal("resource recovery files omitted from inventory")
	}
	resource.Limits.CPUs = 0
	if err := writeJSONAtomic(resourcePath, resource, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("invalid resources accepted during upgrade")
	}
	resource.Limits = proofDockerRuntimeLimits
	if err := writeJSONAtomic(resourcePath, resource, 0600); err != nil {
		t.Fatal(err)
	}
	role.Name = "foreign"
	if err := writeJSONAtomic(rolePath, role, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("foreign role record accepted during upgrade")
	}
	if err := os.Remove(rolePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(resourcePath, filepath.Join(filepath.Dir(resourcePath), "wrong.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("invalid resource filename accepted")
	}
}

func TestUpgradeInventoryValidatesLifecycleResourceMigration(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	before, err := upgradeV2Inventory(s.Profile, d)
	if err != nil {
		t.Fatal(err)
	}
	head := pairV4Test("head")
	if _, err := ensureWorkflowV4ResourceOrigin(s.Profile.Work, head, false); err != nil {
		t.Fatal(err)
	}
	p := s.Profile
	if p.Image == "" {
		p.Image = "approved-image"
	}
	if p.Platform == "" {
		p.Platform = "linux/amd64"
	}
	step, err := retainedWorkflowV4LifecycleStep(p, head, "derive-phase2", filepath.Join(p.Work, "phase2"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	after, err := upgradeV2Inventory(s.Profile, d)
	if err != nil || before.digest() == after.digest() {
		t.Fatal("migration state omitted from inventory", err)
	}
	path := filepath.Join(p.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(head, step.Step)+".json")
	step.Resources.CPUs = 0
	if err := writeJSONAtomic(path, step, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("invalid retained lifecycle allocation accepted")
	}
	step.Resources.CPUs = 2
	if err := writeJSONAtomic(path, step, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(filepath.Dir(path), "wrong.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradeV2Inventory(s.Profile, d); err == nil {
		t.Fatal("foreign lifecycle filename accepted")
	}
}
