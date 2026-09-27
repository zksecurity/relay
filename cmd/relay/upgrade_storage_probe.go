package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

var upgradeProbeName = regexp.MustCompile(`^infrastructure-[0-9a-f]{32}$`)

// A generated, failed setup-only storage probe cannot create a ceremony
// checkpoint. A later completed configure-storage action independently runs the
// storage preflight before writing the ceremony-bound storage configuration.
// Keep the failed record and all other failed actions visible and blocking.
func upgradeSupersededStorageProbe(target guidedProfile, failed upgradeRelatedProfile, activity string, related []upgradeRelatedProfile) bool {
	if target.Role != "coordinator" || activity != filepath.Join(failed.dir, "activity") ||
		failed.profile.Role != "coordinator" || failed.profile.Work != target.Work ||
		failed.profile.ReleaseCommit != target.ReleaseCommit ||
		!strings.HasPrefix(failed.profile.Name, "prep-infrastructure-") {
		return false
	}
	command := failed.profile.Command
	if len(command) != 7 || command[0] != "relay" || command[1] != "coordinator" || command[2] != "check-storage" || command[3] != "--settings" || command[5] != "--out" {
		return false
	}
	settingsName := strings.TrimSuffix(strings.TrimPrefix(command[4], "/work/coordinator-setup/"), ".json")
	if !upgradeProbeName.MatchString(settingsName) || command[4] != "/work/coordinator-setup/"+settingsName+".json" ||
		command[6] != "/work/coordinator-setup/"+settingsName+".checked.json" {
		return false
	}
	settingsPath := filepath.Join(target.Work, "coordinator-setup", settingsName+".json")
	if !regularPreparationFile(settingsPath) {
		return false
	}
	var settings coordinatorStorageSettings
	if setupReadJSON(settingsPath, &settings) != nil || settings.validate() != nil {
		return false
	}
	if _, err := os.Lstat(filepath.Join(target.Work, "coordinator-setup", settingsName+".checked.json")); !os.IsNotExist(err) {
		return false
	}
	old, ok := upgradeLatestAttempt(activity)
	if !ok || old.Success || old.CompletedAt == "" {
		return false
	}
	oldTime, err := time.Parse(time.RFC3339Nano, old.CompletedAt)
	if err != nil {
		return false
	}
	current, err := loadStorageConfig(filepath.Join(target.Work, "ceremony", "config", "relay-storage.json"))
	if err != nil {
		return false
	}
	for _, candidate := range related {
		if candidate.profile.Role != "coordinator" || candidate.profile.Work != target.Work ||
			candidate.profile.ReleaseCommit != target.ReleaseCommit || !strings.HasPrefix(candidate.profile.Name, "prep-storage-") ||
			!upgradeConfigureCommandMatches(candidate.profile.Command, current) {
			continue
		}
		if checkGuidedAttempts(filepath.Join(candidate.dir, "activity")) != nil {
			continue
		}
		completed, ok := upgradeLatestAttempt(filepath.Join(candidate.dir, "activity"))
		if !ok || !completed.Success {
			continue
		}
		completedTime, err := time.Parse(time.RFC3339Nano, completed.CompletedAt)
		if err == nil && completedTime.After(oldTime) {
			fmt.Fprintf(os.Stdout, "Older failed storage setup probe %s was superseded by the completed ceremony storage configuration. Its record remains saved; inspect setup-probes/ for an orphaned test object if the earlier failure included a cleanup error.\n", failed.profile.Name)
			return true
		}
	}
	return false
}

func upgradeLatestAttempt(activity string) (guidedAttempt, bool) {
	var zero guidedAttempt
	entries, err := os.ReadDir(activity)
	if err != nil {
		return zero, false
	}
	for i := len(entries) - 1; i >= 0; i-- {
		name := entries[i].Name()
		if !strings.HasPrefix(name, "attempt-") || !strings.HasSuffix(name, ".json") || !entries[i].Type().IsRegular() {
			continue
		}
		raw, err := readTesseraRegularFile(filepath.Join(activity, name+".done"), 1<<20, true)
		if err != nil || json.Unmarshal(raw, &zero) != nil || zero.CompletedAt == "" {
			return guidedAttempt{}, false
		}
		return zero, true
	}
	return zero, false
}

func upgradeConfigureCommandMatches(command []string, current access.StorageConfig) bool {
	if len(command) < 9 || command[0] != "relay" || command[1] != "coordinator" || command[2] != "configure-storage" || (len(command)-3)%2 != 0 {
		return false
	}
	values := map[string]string{}
	for i := 3; i < len(command); i += 2 {
		if !strings.HasPrefix(command[i], "--") || values[command[i]] != "" || command[i+1] == "" {
			return false
		}
		values[command[i]] = command[i+1]
	}
	if values["--home"] != "/work/ceremony" || values["--coordinator-key"] != "/trust/setup-coordinator.hex" || values["--out"] != "/work/ceremony/config/relay-storage.json" {
		return false
	}
	expected := map[string]string{
		"--provider": current.Provider, "--region": current.Region, "--published-bucket": current.PublishedBucket,
		"--published-base-url": current.PublishedBaseURL, "--inbox-bucket": current.InboxBucket,
		"--profile": current.CoordinatorProfile, "--issuer-profile": current.IssuerProfile,
		"--grant-role-arn": current.GrantRoleARN, "--grant-role-max-ttl": current.GrantRoleMaxTTL,
		"--account-id": current.AccountID, "--endpoint": current.Endpoint,
		"--parent-access-key-id": current.ParentAccessKeyID,
	}
	for key, want := range expected {
		if values[key] != want && !(key == "--region" && current.Provider == "r2" && want == "auto" && values[key] == "") {
			return false
		}
		delete(values, key)
	}
	delete(values, "--home")
	delete(values, "--coordinator-key")
	delete(values, "--out")
	return len(values) == 0
}
