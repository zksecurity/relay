package main

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

var (
	dockerCPUUsagePattern    = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?%$`)
	dockerMemoryUsagePattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?[kKMGTPE]?i?B$`)
)

// Docker's live stats are advisory progress only. A failed sample never affects
// the signed work or the container's reserved limits.
func dockerUsageSnapshot(client dockerCommandClient, containerID string) string {
	osClient, ok := client.(osDockerCommandClient)
	if !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := osClient.command(ctx, "stats", "--no-stream", "--format", "{{json .}}", containerID)
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return "actual CPU/memory unavailable"
	}
	usage, ok := parseDockerUsage(output.Bytes())
	if !ok {
		return "actual CPU/memory unavailable"
	}
	return usage
}

func parseDockerUsage(data []byte) (string, bool) {
	var sample struct {
		CPUPercent string `json:"CPUPerc"`
		Memory     string `json:"MemUsage"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &sample); err != nil {
		return "", false
	}
	parts := strings.Split(sample.Memory, " / ")
	if len(parts) != 2 || !dockerCPUUsagePattern.MatchString(sample.CPUPercent) || !dockerMemoryUsagePattern.MatchString(parts[0]) || !dockerMemoryUsagePattern.MatchString(parts[1]) {
		return "", false
	}
	return "actual CPU " + sample.CPUPercent + "; memory " + parts[0] + " / " + parts[1], true
}
