package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type dockerRoleLaunchRecord struct {
	Schema      string `json:"schema"`
	DaemonID    string `json:"daemon_id"`
	Name        string `json:"name"`
	ContainerID string `json:"container_id,omitempty"`
	ArgsDigest  string `json:"args_digest"`
}

// Ordinary roles contain no contributor entropy lifecycle. Retained containers
// are never adopted or restarted implicitly. Their deterministic operation name
// prevents a lost create response from launching a duplicate computation.
func prepareAdmittedDockerRole(client dockerCommandClient, facts dockerDaemonFacts, o dockerRoleOptions, command, runArgs []string) (containerID string, result error) {
	if len(runArgs) == 0 || runArgs[0] != "run" {
		return "", errors.New("role admission requires Docker run arguments")
	}
	limits, err := resolvedDockerRuntimeLimits(o.runtimeLimits)
	if err != nil {
		return "", err
	}
	identity, _ := json.Marshal(struct {
		Role, Image, Platform, Work, Trust, Keys string
		Command                                  []string
	}{o.role, o.image, o.platform, o.work, o.trust, o.keys, command})
	digest := fmt.Sprintf("%x", sha256.Sum256(identity))
	name := "relay-role-" + digest[:32]
	recordPath := filepath.Join(o.work, "workflow-v4", "role-launches", digest+".json")
	admission, err := acquireDockerCapacity(client, facts, limits)
	if err != nil {
		return "", err
	}
	defer func() { result = errors.Join(result, admission.release()) }()
	var old dockerRoleLaunchRecord
	err = readWorkflowV4JSON(recordPath, &old)
	if err == nil {
		if old.Schema != "relay-role-launch-v1" || old.DaemonID != facts.ID || old.Name != name || !strings.HasPrefix(old.ArgsDigest, "sha256:") || !sha256HexPattern.MatchString(strings.TrimPrefix(old.ArgsDigest, "sha256:")) || (old.ContainerID != "" && !validContainerID(old.ContainerID)) {
			return "", errors.New("retained role launch identity is invalid")
		}
		references := []string{name}
		if old.ContainerID != "" {
			references = append([]string{old.ContainerID}, references...)
		}
		for _, reference := range references {
			_, stderr, inspectErr := client.Output("inspect", "--format", "{{.Id}}", reference)
			if inspectErr == nil {
				return "", fmt.Errorf("retained role container %s requires inspection; refusing a duplicate launch", reference)
			}
			diagnostic := strings.ToLower(string(stderr))
			if !strings.Contains(diagnostic, "no such container") && !strings.Contains(diagnostic, "no such object") {
				return "", fmt.Errorf("cannot establish retained role absence: %s", dockerDiagnostic(stderr, inspectErr))
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	args := append([]string{"create", "--name", name, "--label", "org.zksecurity.relay.operation=" + digest, "--label", "org.zksecurity.relay.role=" + o.role}, runArgs[1:]...)
	raw, _ := json.Marshal(args)
	record := dockerRoleLaunchRecord{Schema: "relay-role-launch-v1", DaemonID: facts.ID, Name: name, ArgsDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
	if err := writeJSONAtomic(recordPath, record, 0600); err != nil {
		return "", err
	}
	stdout, stderr, err := client.Output(args...)
	if err != nil {
		return "", fmt.Errorf("role creation was not confirmed; retained name %s for inspection: %s", name, dockerDiagnostic(stderr, err))
	}
	id := strings.TrimSpace(string(stdout))
	if !validContainerID(id) {
		return "", fmt.Errorf("invalid created role ID; inspect retained name %s", name)
	}
	record.ContainerID = id
	if err := writeJSONAtomic(recordPath, record, 0600); err != nil {
		return "", fmt.Errorf("record created role %s before starting: %w", name, err)
	}
	return id, nil
}
