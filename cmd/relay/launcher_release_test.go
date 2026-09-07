package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReleaseImagePolicy(t *testing.T) {
	commit := strings.Repeat("a", 40)
	records := []map[string]string{}
	for target, name := range map[string]string{"online": "relay-role-online", "offline": "relay-role-offline", "contributor": "relay-ceremony-tool"} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			records = append(records, map[string]string{"target": target, "platform": platform, "source_commit": commit, "image": "ghcr.io/zksecurity/relay/" + name + "@sha256:" + strings.Repeat("b", 64)})
		}
	}
	m := map[string]any{"schema": "relay-role-image-release/v1", "approval": "github-attested-ci", "source_commit": commit, "launcher_commit": commit, "images": records}
	raw, _ := json.Marshal(m)
	for _, role := range []string{"coordinator", "participant", "keygen", "release-signer", "witness", "mirror", "auditor", "upload-station", "decision-signer"} {
		for _, platform := range []string{"linux/amd64", "linux/arm64"} {
			if _, err := selectReleaseImage(raw, commit, role, platform); err != nil {
				t.Fatal(role, platform, err)
			}
		}
	}
	for _, field := range []string{"schema", "approval", "source_commit", "launcher_commit"} {
		original := m[field]
		m[field] = "invalid"
		bad, _ := json.Marshal(m)
		if _, err := selectReleaseImage(bad, commit, "coordinator", "linux/arm64"); err == nil {
			t.Fatal("accepted invalid", field)
		}
		m[field] = original
	}
	original := records[0]["image"]
	records[0]["image"] = "ghcr.io/attacker/relay@sha256:" + strings.Repeat("b", 64)
	bad, _ := json.Marshal(m)
	if _, err := selectReleaseImage(bad, commit, "coordinator", "linux/arm64"); err == nil {
		t.Fatal("accepted foreign registry namespace")
	}
	records[0]["image"] = original
	records[0] = records[1]
	bad, _ = json.Marshal(m)
	if _, err := selectReleaseImage(bad, commit, "coordinator", "linux/arm64"); err == nil {
		t.Fatal("accepted duplicate image")
	}
	if err := checkLauncherRelease(strings.Repeat("0", 40)); err == nil {
		t.Fatal("accepted incompatible launcher")
	}
}
