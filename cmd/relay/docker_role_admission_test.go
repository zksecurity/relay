package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerRoleAdmissionRetainsCreatedIdentity(t *testing.T) {
	o := roleTestOptions(t)
	fake := &dockerClientFake{platform: o.platform, daemonID: "role-admission-" + t.TempDir()}
	facts, err := inspectDockerDaemon(fake, "test-local", "unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(dockerResourcePolicyPath(facts.ID))) })
	command := []string{"mpc-ceremony", "phase2", "init"}
	argv, err := dockerRoleArgs(o, command, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	fake.onCreate = func() {
		lock, err := acquireDockerAdmission(facts)
		if err == nil {
			lock.release()
			t.Error("role creation escaped admission lock")
		}
	}
	id, err := prepareAdmittedDockerRole(fake, facts, o, command, argv)
	if err != nil || id != testContainerID {
		t.Fatal("role create failed", id, err)
	}
	lock, err := acquireDockerAdmission(facts)
	if err != nil {
		t.Fatal("role creation kept lock", err)
	}
	lock.release()
	records, err := filepath.Glob(filepath.Join(o.work, "workflow-v4", "role-launches", "*.json"))
	if err != nil || len(records) != 1 {
		t.Fatal("missing role record", err)
	}
	var record dockerRoleLaunchRecord
	if err := readWorkflowV4JSON(records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record.ContainerID != id || !strings.HasPrefix(record.Name, "relay-role-") {
		t.Fatal("role identity not recorded")
	}
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err == nil || !strings.Contains(err.Error(), "retained role container") {
		t.Fatal("duplicate role allowed", err)
	}
	fake.removed = true
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err != nil {
		t.Fatal("verified absent role prevented subsequent execution", err)
	}
	record.ArgsDigest = "corrupt"
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(records[0], raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err == nil {
		t.Fatal("corrupt role record accepted")
	}
}

func TestDockerRoleAdmissionLostCreateResponseRetainsIntent(t *testing.T) {
	o := roleTestOptions(t)
	fake := &dockerClientFake{platform: o.platform, daemonID: "lost-role-" + t.TempDir(), createErrAfter: true}
	facts, err := inspectDockerDaemon(fake, "test-local", "unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(dockerResourcePolicyPath(facts.ID))) })
	command := []string{"mpc-ceremony", "phase2", "init"}
	argv, err := dockerRoleArgs(o, command, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err == nil {
		t.Fatal("lost response accepted")
	}
	records, _ := filepath.Glob(filepath.Join(o.work, "workflow-v4", "role-launches", "*.json"))
	if len(records) != 1 {
		t.Fatal("lost response discarded intent")
	}
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err == nil || !strings.Contains(err.Error(), "retained role container") {
		t.Fatal("lost create response caused duplicate launch", err)
	}
}

type renamedRoleDockerClient struct{ *dockerClientFake }

func (c renamedRoleDockerClient) Output(args ...string) ([]byte, []byte, error) {
	if len(args) == 4 && args[0] == "inspect" && strings.HasPrefix(args[3], "relay-role-") {
		return nil, []byte("No such container"), errors.New("not found")
	}
	return c.dockerClientFake.Output(args...)
}

func TestDockerRoleAdmissionDoesNotLoseRenamedContainer(t *testing.T) {
	o := roleTestOptions(t)
	fake := &dockerClientFake{platform: o.platform, daemonID: "renamed-role-" + t.TempDir()}
	facts, err := inspectDockerDaemon(fake, "test-local", "unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(dockerResourcePolicyPath(facts.ID))) })
	command := []string{"mpc-ceremony", "phase2", "init"}
	argv, err := dockerRoleArgs(o, command, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAdmittedDockerRole(fake, facts, o, command, argv); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAdmittedDockerRole(renamedRoleDockerClient{fake}, facts, o, command, argv); err == nil || !strings.Contains(err.Error(), testContainerID) {
		t.Fatal("renamed container caused duplicate launch", err)
	}
}
