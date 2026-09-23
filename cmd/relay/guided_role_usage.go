package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// The guided parent can observe the exact retained role container while its
// child has replaced itself with `docker start --attach`. This calculation
// mirrors the durable role-launch identity, so concurrent roles are never
// confused with one another for progress display.
func guidedRoleUsageRecord(args []string) (string, string, bool) {
	if len(args) < 3 || args[0] != "role" {
		return "", "", false
	}
	values := map[string]string{}
	var command []string
	for index := 1; index < len(args); index++ {
		if args[index] == "--" {
			command = args[index+1:]
			break
		}
		if !strings.HasPrefix(args[index], "--") || index+1 >= len(args) {
			return "", "", false
		}
		values[args[index]] = args[index+1]
		index++
	}
	if len(command) == 0 || values["--role"] == "" || values["--image"] == "" || values["--platform"] == "" || !filepath.IsAbs(values["--work"]) {
		return "", "", false
	}
	identity, err := json.Marshal(struct {
		Role, Image, Platform, Work, Trust, Keys string
		Command                                  []string
	}{values["--role"], values["--image"], values["--platform"], values["--work"], values["--trust"], values["--keys"], command})
	if err != nil {
		return "", "", false
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(identity))
	binary := values["--docker-cli"]
	if binary == "" {
		binary = "docker"
	}
	return filepath.Join(values["--work"], "workflow-v4", "role-launches", digest+".json"), binary, true
}

func guidedRoleUsageSnapshot(args []string) string {
	path, binary, ok := guidedRoleUsageRecord(args)
	if !ok {
		return ""
	}
	var record dockerRoleLaunchRecord
	if err := readWorkflowV4JSON(path, &record); err != nil || record.Schema != "relay-role-launch-v1" || !validContainerID(record.ContainerID) {
		return ""
	}
	client := osDockerCommandClient{binary: binary}
	contextName, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return "actual CPU/memory unavailable"
	}
	bound := client.BindHost(endpoint)
	daemon, err := inspectDockerDaemon(bound, contextName, endpoint)
	if err != nil || daemon.ID != record.DaemonID {
		return "actual CPU/memory unavailable"
	}
	return dockerUsageSnapshot(bound, record.ContainerID)
}
